defmodule TeiserverWeb.Firebase.TokenControllerTest do
  alias Ecto.UUID
  alias Joken.Signer
  alias JOSE.JWK
  alias Teiserver.Account
  alias Teiserver.Account.Guardian
  alias Teiserver.BotFixtures
  alias Teiserver.Helpers.GeneralTestLib
  alias Teiserver.OAuth
  alias Teiserver.OAuthFixtures

  use TeiserverWeb.ConnCase, async: false

  @email "svc@example.iam.gserviceaccount.com"

  setup_all do
    jwk = JWK.generate_key({:rsa, 2048})
    {_alg, private_pem} = JWK.to_pem(jwk)
    {_alg, public_pem} = jwk |> JWK.to_public() |> JWK.to_pem()

    %{private_pem: private_pem, public_pem: public_pem}
  end

  # runtime.exs reads TEI_FIREBASE_* from the environment, so never rely on the
  # ambient config - pin it for every test.
  setup %{conn: conn, private_pem: private_pem} do
    original = Application.get_env(:teiserver, :firebase)
    on_exit(fn -> Application.put_env(:teiserver, :firebase, original) end)
    Application.put_env(:teiserver, :firebase, email: @email, private_key: private_pem)

    {:ok, conn: put_req_header(conn, "accept", "application/json")}
  end

  defp get_token(conn, bearer) do
    conn
    |> put_req_header("authorization", "Bearer #{bearer}")
    |> get(~p"/teiserver/api/firebase_token")
  end

  defp assert_valid_token(resp, user, public_pem) do
    body = json_response(resp, 200)
    assert body["uid"] == to_string(user.id)

    assert {:ok, claims} =
             Joken.verify(body["token"], Signer.create("RS256", %{"pem" => public_pem}))

    assert claims["uid"] == to_string(user.id)
    assert claims["iss"] == @email
    body
  end

  describe "rejecting bad credentials" do
    test "no authorization header", %{conn: conn} do
      resp = get(conn, ~p"/teiserver/api/firebase_token")
      assert json_response(resp, 401) == %{"error" => "unauthenticated"}
    end

    test "unparseable bearer token", %{conn: conn} do
      assert json_response(get_token(conn, "nope"), 401) == %{"error" => "invalid_token"}
    end

    test "empty bearer token", %{conn: conn} do
      assert json_response(get_token(conn, "   "), 401) == %{"error" => "invalid_token"}
    end
  end

  describe "guardian tokens" do
    test "mints a token", %{conn: conn, public_pem: public_pem} do
      user = GeneralTestLib.make_user()
      {:ok, token, _claims} = Guardian.encode_and_sign(user)

      assert_valid_token(get_token(conn, token), user, public_pem)
    end

    test "rejects a refresh token", %{conn: conn} do
      user = GeneralTestLib.make_user()
      {:ok, token, _claims} = Guardian.encode_and_sign(user, %{}, token_type: "refresh")

      assert json_response(get_token(conn, token), 401) == %{"error" => "invalid_token"}
    end
  end

  describe "oauth tokens" do
    test "mints a token when the firebase scope is held", %{conn: conn, public_pem: public_pem} do
      user = GeneralTestLib.make_user()
      %{token: token} = OAuthFixtures.setup_token(user, scopes: ["firebase"])

      assert_valid_token(get_token(conn, token.value), user, public_pem)
    end

    test "rejects a token without the firebase scope", %{conn: conn} do
      user = GeneralTestLib.make_user()
      %{token: token} = OAuthFixtures.setup_token(user, scopes: ["tachyon.lobby"])

      assert json_response(get_token(conn, token.value), 401) == %{"error" => "invalid_token"}
    end

    test "rejects a refresh token", %{conn: conn} do
      user = GeneralTestLib.make_user()
      %{app: app} = OAuthFixtures.setup_token(user, scopes: ["firebase"])

      refresh =
        OAuthFixtures.token_attrs(user, app)
        |> Map.put(:type, :refresh)
        |> OAuthFixtures.create_token()

      assert json_response(get_token(conn, refresh.value), 401) == %{"error" => "invalid_token"}
    end

    test "rejects an expired token", %{conn: conn} do
      user = GeneralTestLib.make_user()
      %{app: app} = OAuthFixtures.setup_token(user, scopes: ["firebase"])

      expired =
        OAuthFixtures.token_attrs(user, app)
        |> Map.put(:expires_at, DateTime.add(DateTime.utc_now(), -60, :second))
        |> OAuthFixtures.create_token()

      assert json_response(get_token(conn, expired.value), 401) == %{"error" => "invalid_token"}
    end

    # A bot token has no owner_id; it must not resolve to a user
    test "rejects a bot owned token", %{conn: conn} do
      user = GeneralTestLib.make_user()
      bot = BotFixtures.create_bot()

      app =
        OAuthFixtures.app_attrs(user.id)
        |> Map.merge(%{uid: "firebase_bot_app", scopes: ["firebase"]})
        |> OAuthFixtures.create_app()

      token = OAuthFixtures.token_attrs(bot, app) |> OAuthFixtures.create_token()

      assert json_response(get_token(conn, token.value), 401) == %{"error" => "invalid_token"}
    end
  end

  describe "account user tokens" do
    # This path used to raise on an undefined Timex call, turning a valid
    # credential into a 500
    test "mints a token and stamps last_used", %{conn: conn, public_pem: public_pem} do
      user = GeneralTestLib.make_user()

      {:ok, user_token} =
        Account.create_user_token(%{
          value: UUID.generate(),
          user_id: user.id,
          user_agent: "test",
          ip: "127.0.0.1",
          expires: DateTime.add(DateTime.utc_now(:second), 1, :day)
        })

      assert user_token.last_used == nil
      assert_valid_token(get_token(conn, user_token.value), user, public_pem)
      assert %DateTime{} = Account.get_user_token!(user_token.id).last_used
    end

    test "accepts a token with no expiry", %{conn: conn, public_pem: public_pem} do
      user = GeneralTestLib.make_user()

      {:ok, user_token} =
        Account.create_user_token(%{value: UUID.generate(), user_id: user.id})

      assert_valid_token(get_token(conn, user_token.value), user, public_pem)
    end

    test "rejects an expired token", %{conn: conn} do
      user = GeneralTestLib.make_user()

      {:ok, user_token} =
        Account.create_user_token(%{
          value: UUID.generate(),
          user_id: user.id,
          expires: DateTime.add(DateTime.utc_now(:second), -1, :day)
        })

      assert json_response(get_token(conn, user_token.value), 401) == %{
               "error" => "invalid_token"
             }
    end
  end

  describe "restricted accounts" do
    # A firebase session outlives the teiserver token that created it, so a
    # banned user must never get one
    test "rejects a user restricted from logging in", %{conn: conn} do
      user = GeneralTestLib.make_user(%{"restrictions" => ["Login"]})
      {:ok, token, _claims} = Guardian.encode_and_sign(user)

      assert json_response(get_token(conn, token), 403) == %{"error" => "account_restricted"}
    end

    test "rejects a smurf", %{conn: conn} do
      origin = GeneralTestLib.make_user()
      smurf = GeneralTestLib.make_user()
      {:ok, smurf} = Account.update_user_smurf(smurf, %{smurf_of_id: origin.id})
      %{token: token} = OAuthFixtures.setup_token(smurf, scopes: ["firebase"])

      assert json_response(get_token(conn, token.value), 403) == %{
               "error" => "account_restricted"
             }
    end
  end

  describe "when firebase is not configured" do
    test "reports the missing email", %{conn: conn} do
      Application.put_env(:teiserver, :firebase, email: nil, private_key: nil)
      user = GeneralTestLib.make_user()
      {:ok, token, _claims} = Guardian.encode_and_sign(user)

      assert json_response(get_token(conn, token), 500) == %{
               "error" => "firebase email is not configured"
             }
    end

    test "reports the missing private key", %{conn: conn} do
      Application.put_env(:teiserver, :firebase, email: @email, private_key: nil)
      user = GeneralTestLib.make_user()
      {:ok, token, _claims} = Guardian.encode_and_sign(user)

      assert json_response(get_token(conn, token), 500) == %{
               "error" => "firebase private key is not configured"
             }
    end

    test "does not leak key material when the key is malformed", %{conn: conn} do
      Application.put_env(:teiserver, :firebase, email: @email, private_key: "-----BEGIN junk")
      user = GeneralTestLib.make_user()
      {:ok, token, _claims} = Guardian.encode_and_sign(user)

      assert json_response(get_token(conn, token), 500) == %{
               "error" => "Failed to generate token"
             }
    end
  end

  describe "scope registration" do
    test "firebase is a grantable scope" do
      assert "firebase" in OAuth.allowed_scopes()
    end
  end
end
