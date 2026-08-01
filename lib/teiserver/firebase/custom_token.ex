defmodule Teiserver.Firebase.CustomToken do
  @moduledoc """
  Generates [Firebase custom auth tokens](https://firebase.google.com/docs/auth/admin/create-custom-tokens)
  for Teiserver users.

  A custom token is a short lived RS256 JWT signed with a Google service
  account key. Firebase exchanges it for a Firebase session that the client can
  refresh indefinitely, so handing one out is equivalent to signing that user in
  to Firebase - only do so for a user who is allowed to log in right now.
  """

  alias Joken.Signer
  alias JOSE.JWK

  @aud "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
  @ttl_seconds 3600
  # Firebase caps uids at 128 characters
  @max_uid_length 128

  @type config :: %{email: String.t(), private_key: String.t()}
  @type error :: {:not_configured, String.t()} | :invalid_uid | :signing_failed

  @doc """
  Reads and normalises the Firebase service account credentials.

  Returns `{:error, {:not_configured, key}}` when the deployment hasn't set
  them, which is the expected state for local development.
  """
  @spec config() :: {:ok, config()} | {:error, error()}
  def config do
    config = Application.get_env(:teiserver, :firebase, [])
    email = Keyword.get(config, :email)
    private_key = Keyword.get(config, :private_key)

    cond do
      blank?(email) ->
        {:error, {:not_configured, "firebase email"}}

      blank?(private_key) ->
        {:error, {:not_configured, "firebase private key"}}

      true ->
        {:ok, %{email: String.trim(email), private_key: normalize_private_key(private_key)}}
    end
  end

  @doc """
  Generates a custom token for `uid`, valid for an hour.

  Errors are deliberately opaque atoms: the failure modes here all involve the
  private key, and the reason ends up in logs and error responses.
  """
  @spec generate(String.t(), config()) :: {:ok, String.t()} | {:error, error()}
  def generate(uid, %{email: email, private_key: private_key})
      when is_binary(uid) and byte_size(uid) > 0 and byte_size(uid) <= @max_uid_length do
    now = System.os_time(:second)

    claims = %{
      "iss" => email,
      "sub" => email,
      "aud" => @aud,
      "iat" => now,
      "exp" => now + @ttl_seconds,
      "uid" => uid
    }

    sign(claims, private_key)
  end

  def generate(_uid, _config), do: {:error, :invalid_uid}

  @doc "The `aud` claim Firebase expects on a custom token."
  @spec audience() :: String.t()
  def audience, do: @aud

  # Joken.Signer.create/2 raises on a malformed key, and the exception report
  # would carry the PEM into the logs, so nothing may escape this function but
  # a bare atom.
  defp sign(claims, private_key) do
    with {:ok, signer} <- signer(private_key),
         {:ok, token, _claims} <- Joken.generate_and_sign(%{}, claims, signer) do
      {:ok, token}
    else
      _error -> {:error, :signing_failed}
    end
  rescue
    _exception -> {:error, :signing_failed}
  end

  defp signer(private_key) do
    case Signer.create("RS256", %{"pem" => private_key}) do
      %Signer{jwk: %JWK{}} = signer -> {:ok, signer}
      _other -> {:error, :signing_failed}
    end
  end

  defp blank?(value), do: !is_binary(value) || String.trim(value) == ""

  # Service account keys are commonly pasted into env vars wrapped in quotes
  # and with literal "\n" instead of newlines.
  defp normalize_private_key(private_key) do
    private_key
    |> String.trim()
    |> String.trim("\"")
    |> String.replace("\\n", "\n")
    |> String.trim()
  end
end
