import axios from "axios";
import { getCsrfToken } from "./authStore";

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

export const apiClient = axios.create({
  baseURL: apiBaseUrl,
  withCredentials: true,
  headers: {
    "Content-Type": "application/json"
  }
});

apiClient.interceptors.request.use((config) => {
  const method = (config.method ?? "get").toLowerCase();
  const csrf = getCsrfToken();

  if (csrf && ["post", "put", "patch", "delete"].includes(method)) {
    // CSRF header name must match backend config
    (config.headers ??= {})["X-CSRF-Token"] = csrf;
  }

  return config;
});


