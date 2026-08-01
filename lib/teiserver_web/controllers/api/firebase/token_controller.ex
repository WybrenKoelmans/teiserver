defmodule TeiserverWeb.API.Firebase.TokenController do
  alias Plug.Conn
  alias Teiserver.Firebase.CustomToken

  use TeiserverWeb, :controller

  require Logger

  @doc """
  Mints a Firebase custom token for the calling user.

  `Teiserver.Account.ApiAuthPlug` halts the pipeline unless there is an
  authenticated, unrestricted user, so `:current_user` is always present here.
  """
  @spec index(Conn.t(), map()) :: Conn.t()
  def index(conn, _params) do
    uid = to_string(conn.assigns.current_user.id)

    with {:ok, config} <- CustomToken.config(),
         {:ok, token} <- CustomToken.generate(uid, config) do
      json(conn, %{token: token, uid: uid})
    else
      {:error, {:not_configured, key}} ->
        Logger.error("Firebase custom token requested but #{key} is not configured")

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "#{key} is not configured"})

      {:error, reason} ->
        # reason is always an opaque atom - key material must not reach a log
        # line or a response body
        Logger.error("Unable to generate a firebase custom token for #{uid}: #{inspect(reason)}")

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to generate token"})
    end
  end
end
