import axios from "axios";
import type { AxiosError } from "axios";

const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const WS_URL = import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8000";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function truncate(value: string, maxLength = 120): string {
  if (value.length <= maxLength) return value;
  return value.slice(0, maxLength) + "...";
}

function extractDetailMessage(error: unknown): string {
  if (error instanceof TypeError) {
    return truncate(escapeHtml(error.message), 120);
  }

  const axiosError = error as AxiosError<{ detail?: unknown }>;
  const data = axiosError.response?.data;

  if (data && typeof data === "object") {
    const detail = (data as { detail?: unknown }).detail;
    if (typeof detail === "string") {
      return truncate(escapeHtml(detail), 120);
    }
    if (Array.isArray(detail)) {
      const text = detail.map((item) => (typeof item === "string" ? item : JSON.stringify(item))).join("; ");
      return truncate(escapeHtml(text), 120);
    }
    if (detail && typeof detail === "object") {
      return truncate(escapeHtml(JSON.stringify(detail)), 120);
    }
    return truncate(escapeHtml(JSON.stringify(data)), 120);
  }

  if (axiosError.response) {
    return `请求失败 (HTTP ${axiosError.response.status})`;
  }

  if (error instanceof Error) {
    return truncate(escapeHtml(error.message), 120);
  }

  return "请求失败，请稍后重试";
}

function getAccessToken(): string {
  if (typeof window !== "undefined") {
    return localStorage.getItem("access_token") || "";
  }
  return "";
}

const httpClient = axios.create({ baseURL: API_BASE });

httpClient.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token && !config.headers?.Authorization) {
    config.headers = { ...config.headers, Authorization: `Bearer ${token}` };
  }
  return config;
});

httpClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    if (status === 401) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("access_token");
        window.location.href = "/login";
      }
    }
    const message = extractDetailMessage(error);
    const enhancedError = new Error(message) as Error & { response?: { data?: unknown; status?: number } };
    enhancedError.response = error.response;
    return Promise.reject(enhancedError);
  }
);

export function getApiErrorMessage(error: unknown): string {
  if (error instanceof Error && "response" in error) {
    return extractDetailMessage(error);
  }
  return extractDetailMessage(error);
}

export const api = {
  getThreats: (params?: { limit?: number; offset?: number }) =>
    httpClient.get<{
      total: number;
      limit: number;
      offset: number;
      items: Array<{
        id: string;
        file_id: string;
        name: string;
        type: string;
        severity: string;
        status: string;
        confidence: number;
        yara_matches?: string[] | null;
        sandbox_behavior?: string[] | null;
      }>;
    }>("/api/threats", { params }),

  scanUpload: (file: File, onProgress: (progress: number) => void) => {
    return new Promise<{ status: string; threat?: unknown }>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const formData = new FormData();
      formData.append("file", file);

      const token = getAccessToken();

      xhr.upload.addEventListener("progress", (event) => {
        if (event.lengthComputable) {
          const percent = Math.round((event.loaded / event.total) * 90);
          onProgress(percent);
        }
      });

      xhr.addEventListener("load", () => {
        let payload: { status: string; threat?: unknown } = { status: "safe" };
        if (xhr.status === 200 && xhr.responseText) {
          try {
            payload = JSON.parse(xhr.responseText);
          } catch {
            payload = { status: "safe" };
          }
        }

        if (xhr.status < 200 || xhr.status >= 300) {
          const err = new Error(`HTTP ${xhr.status}`) as Error & { response?: { data?: unknown; status?: number } };
          err.response = { data: payload, status: xhr.status };
          reject(err);
          return;
        }

        resolve(payload);
      });

      xhr.addEventListener("error", () => reject(new TypeError("网络请求失败")));
      xhr.addEventListener("abort", () => reject(new Error("上传已取消")));

      xhr.open("POST", `${API_BASE}/api/scan/upload`);
      if (token) {
        xhr.setRequestHeader("Authorization", `Bearer ${token}`);
      }
      xhr.send(formData);
    });
  },

  quarantine: (id: string, signal?: AbortSignal) =>
    httpClient.request<{ status: string }>({ url: `/api/threats/${encodeURIComponent(id)}/quarantine`, method: "POST", signal }),
  restore: (id: string, signal?: AbortSignal) =>
    httpClient.request<{ status: string }>({ url: `/api/threats/${encodeURIComponent(id)}/restore`, method: "POST", signal }),
  permanentlyDelete: (id: string, signal?: AbortSignal) =>
    httpClient.request<{ status: string }>({ url: `/api/threats/${encodeURIComponent(id)}/permanently_delete`, method: "POST", signal }),
  clean: (id: string, signal?: AbortSignal) =>
    httpClient.request<{ status: string }>({ url: `/api/threats/${encodeURIComponent(id)}/clean`, method: "POST", signal }),
  exportReport: () =>
    httpClient.get<{
      generated_at: string;
      summary: Record<string, unknown>;
      threats: Array<{
        id: string;
        file_id: string;
        name: string;
        type: string;
        severity: string;
        status: string;
        confidence: number;
        yara_matches?: string[] | null;
        sandbox_behavior?: string[] | null;
      }>;
    }>("/api/reports/export"),
};

export { WS_URL };
