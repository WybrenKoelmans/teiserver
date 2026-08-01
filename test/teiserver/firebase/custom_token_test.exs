defmodule Teiserver.Firebase.CustomTokenTest do
  alias Joken.Signer
  alias JOSE.JWK
  alias Teiserver.Firebase.CustomToken

  use ExUnit.Case, async: false

  setup_all do
    jwk = JWK.generate_key({:rsa, 2048})
    {_alg, private_pem} = JWK.to_pem(jwk)
    {_alg, public_pem} = jwk |> JWK.to_public() |> JWK.to_pem()

    %{private_pem: private_pem, public_pem: public_pem}
  end

  setup do
    original = Application.get_env(:teiserver, :firebase)
    on_exit(fn -> Application.put_env(:teiserver, :firebase, original) end)
    :ok
  end

  defp put_config(email, private_key) do
    Application.put_env(:teiserver, :firebase, email: email, private_key: private_key)
  end

  defp verify(token, public_pem) do
    Joken.verify(token, Signer.create("RS256", %{"pem" => public_pem}))
  end

  describe "config/0" do
    test "reports which key is missing" do
      put_config(nil, nil)
      assert CustomToken.config() == {:error, {:not_configured, "firebase email"}}

      put_config("svc@example.iam.gserviceaccount.com", nil)
      assert CustomToken.config() == {:error, {:not_configured, "firebase private key"}}
    end

    test "treats a blank value as unset", %{private_pem: private_pem} do
      put_config("   ", private_pem)
      assert CustomToken.config() == {:error, {:not_configured, "firebase email"}}

      put_config("svc@example.iam.gserviceaccount.com", "  \n ")
      assert CustomToken.config() == {:error, {:not_configured, "firebase private key"}}
    end

    test "unwraps a key pasted into an env var", %{private_pem: private_pem} do
      escaped = "\"" <> String.replace(private_pem, "\n", "\\n") <> "\""
      put_config("svc@example.iam.gserviceaccount.com", escaped)

      assert {:ok, config} = CustomToken.config()
      assert config.private_key == String.trim(private_pem)
    end
  end

  describe "generate/2" do
    test "signs a token firebase can verify", %{private_pem: private_pem, public_pem: public_pem} do
      put_config("svc@example.iam.gserviceaccount.com", private_pem)
      {:ok, config} = CustomToken.config()

      before = System.os_time(:second)
      assert {:ok, token} = CustomToken.generate("1234", config)

      assert {:ok, claims} = verify(token, public_pem)
      assert claims["uid"] == "1234"
      assert claims["aud"] == CustomToken.audience()
      assert claims["iss"] == "svc@example.iam.gserviceaccount.com"
      assert claims["sub"] == "svc@example.iam.gserviceaccount.com"
      assert claims["iat"] >= before
      assert claims["exp"] == claims["iat"] + 3600
    end

    test "uses RS256", %{private_pem: private_pem} do
      put_config("svc@example.iam.gserviceaccount.com", private_pem)
      {:ok, config} = CustomToken.config()

      assert {:ok, token} = CustomToken.generate("1234", config)
      [header, _payload, _signature] = String.split(token, ".")
      assert {:ok, decoded} = Base.url_decode64(header, padding: false)
      assert Jason.decode!(decoded)["alg"] == "RS256"
    end

    test "does not verify against a different key", %{private_pem: private_pem} do
      put_config("svc@example.iam.gserviceaccount.com", private_pem)
      {:ok, config} = CustomToken.config()
      assert {:ok, token} = CustomToken.generate("1234", config)

      other_public =
        {:rsa, 2048}
        |> JWK.generate_key()
        |> JWK.to_public()
        |> JWK.to_pem()
        |> elem(1)

      assert {:error, :signature_error} = verify(token, other_public)
    end

    # Joken.Signer.create/2 raises on a bad key, and the exception report would
    # put the private key in the logs.
    test "returns an opaque error instead of raising on a malformed key" do
      for bad_key <- [
            "not a pem at all",
            "-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----"
          ] do
        assert CustomToken.generate("1234", %{email: "svc@example.com", private_key: bad_key}) ==
                 {:error, :signing_failed}
      end
    end

    test "rejects uids firebase would reject", %{private_pem: private_pem} do
      put_config("svc@example.iam.gserviceaccount.com", private_pem)
      {:ok, config} = CustomToken.config()

      too_long = String.duplicate("x", 129)
      longest_allowed = String.duplicate("x", 128)

      assert CustomToken.generate("", config) == {:error, :invalid_uid}
      assert CustomToken.generate(too_long, config) == {:error, :invalid_uid}
      assert {:ok, _token} = CustomToken.generate(longest_allowed, config)
    end
  end
end
