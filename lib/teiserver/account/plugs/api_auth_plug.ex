defmodule Teiserver.Account.ApiAuthPlug do
  @moduledoc """
  Authenticates a JSON API request from an `Authorization: Bearer <token>`
  header, assigning `:current_user` and `:user_token`.

  Three credential types are accepted, tried in order:

    * a Guardian access token - the same credential the web session uses
    * an OAuth access token
    * an account user token - a personal API token

  Guardian and account user tokens are the user acting as themselves, so they
  carry no scopes. OAuth tokens are delegated to a third party application, so
  they must hold every scope named in the plug's `:scopes` option; without that
  option no scope check happens at all, so always set it on privileged routes.

  Users restricted from logging in, or flagged as a smurf, are rejected however
  they authenticated. This mirrors `Teiserver.Account.AuthPlug` - without it a
  banned user would keep a working credential on the API.
  """

  alias Phoenix.Controller
  alias Teiserver.Account
  alias Teiserver.Account.Guardian
  alias Teiserver.Account.UserToken
  alias Teiserver.OAuth

  require Logger

  import Plug.Conn

  @behaviour Plug

  def init(opts), do: opts

  def call(conn, opts) do
    with {:ok, raw_token} <- bearer_token(conn),
         {:ok, user} <- authenticate(raw_token, opts),
         :ok <- login_allowed?(user) do
      conn
      |> assign(:current_user, user)
      |> assign(:user_token, raw_token)
    else
      {:error, :restricted} -> error_response(conn, :forbidden, "account_restricted")
      {:error, reason} -> error_response(conn, :unauthorized, reason)
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> raw_token] ->
        case String.trim(raw_token) do
          "" -> {:error, "invalid_token"}
          token -> {:ok, token}
        end

      _other ->
        {:error, "unauthenticated"}
    end
  end

  defp authenticate(raw_token, opts) do
    strategies = [
      fn -> authenticate_guardian(raw_token) end,
      fn -> authenticate_oauth(raw_token, opts) end,
      fn -> authenticate_user_token(raw_token) end
    ]

    Enum.find_value(strategies, {:error, "invalid_token"}, fn strategy ->
      case strategy.() do
        {:ok, user} -> {:ok, user}
        {:error, _reason} -> nil
      end
    end)
  end

  # Constrained to access tokens to match Teiserver.Account.AuthPipeline, so a
  # refresh token can't be swapped in here.
  defp authenticate_guardian(raw_token) do
    case Guardian.resource_from_token(raw_token, %{"typ" => "access"}) do
      {:ok, %Account.User{} = user, _claims} -> {:ok, user}
      _error -> {:error, :invalid_token}
    end
  end

  defp authenticate_oauth(raw_token, opts) do
    with {:ok, token} <- OAuth.get_valid_token(raw_token),
         :ok <- access_token?(token),
         :ok <- has_all_scopes?(token, opts[:scopes]),
         {:ok, user_id} <- token_owner_id(token) do
      fetch_user(user_id)
    end
  end

  defp authenticate_user_token(raw_token) do
    with %UserToken{} = token <- Account.get_user_token_by_value(raw_token),
         :ok <- user_token_live?(token),
         {:ok, user_id} <- token_owner_id(token),
         {:ok, user} <- fetch_user(user_id) do
      touch_user_token(token)
      {:ok, user}
    else
      nil -> {:error, :no_token}
      {:error, reason} -> {:error, reason}
    end
  end

  defp access_token?(%OAuth.Token{type: :access}), do: :ok
  defp access_token?(_token), do: {:error, :invalid_token}

  defp has_all_scopes?(_token, nil), do: :ok

  defp has_all_scopes?(token, requested_scopes) do
    diff = requested_scopes |> MapSet.new() |> MapSet.difference(MapSet.new(token.scopes))

    if Enum.empty?(diff) do
      :ok
    else
      {:error, :insufficient_scope}
    end
  end

  defp user_token_live?(%UserToken{expires: nil}), do: :ok

  defp user_token_live?(%UserToken{expires: expires}) do
    if DateTime.compare(DateTime.utc_now(), expires) == :lt do
      :ok
    else
      {:error, :expired}
    end
  end

  defp touch_user_token(token) do
    case Account.update_user_token(token, %{last_used: DateTime.utc_now(:second)}) do
      {:ok, _token} ->
        :ok

      {:error, changeset} ->
        Logger.warning("Unable to stamp last_used on user token: #{inspect(changeset.errors)}")
        :ok
    end
  end

  # An OAuth token can belong to a bot instead of a user, in which case
  # owner_id is nil - such a token must never resolve to a user here.
  defp token_owner_id(%OAuth.Token{owner_id: user_id}) when is_integer(user_id),
    do: {:ok, user_id}

  defp token_owner_id(%OAuth.Token{}), do: {:error, :not_a_user_token}

  defp token_owner_id(%UserToken{user_id: user_id}) when is_integer(user_id),
    do: {:ok, user_id}

  defp token_owner_id(%UserToken{}), do: {:error, :no_user}

  defp fetch_user(user_id) do
    case Account.get_user(user_id) do
      nil -> {:error, :no_user}
      user -> {:ok, user}
    end
  end

  # Mirrors Teiserver.Account.AuthPlug.banned_user?/1
  defp login_allowed?(%Account.User{} = user) do
    cond do
      user.smurf_of_id != nil -> {:error, :restricted}
      Account.restricted?(user, ["Login"]) -> {:error, :restricted}
      true -> :ok
    end
  end

  defp error_response(conn, status, reason) do
    conn
    |> put_status(status)
    |> Controller.json(%{error: reason})
    |> halt()
  end
end
