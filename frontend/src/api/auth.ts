import { apiClient } from "./client";
import { setCsrfToken } from "./authStore";

export interface MaskedUser {
  id: string;
  email_masked: string;
  role: "admin" | "user" | "guest";
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  user: MaskedUser;
  csrf_token: string;
}

export async function login(email: string, password: string): Promise<MaskedUser> {
  const { data } = await apiClient.post<AuthResponse>("/auth/login", { email, password });
  setCsrfToken(data.csrf_token);
  return data.user;
}

export async function register(email: string, password: string): Promise<MaskedUser> {
  const { data } = await apiClient.post<AuthResponse>("/auth/register", { email, password });
  setCsrfToken(data.csrf_token);
  return data.user;
}

export async function logout(): Promise<void> {
  await apiClient.post("/auth/logout");
}

export async function fetchCurrentUser(): Promise<MaskedUser | null> {
  try {
    const { data } = await apiClient.get<AuthResponse>("/auth/me");
    setCsrfToken(data.csrf_token);
    return data.user;
  } catch (err) {
    return null;
  }
}


