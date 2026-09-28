import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getApiErrorMessage(error: unknown): string {
  let message = "请求失败，请稍后重试";

  if (error instanceof TypeError) {
    return message;
  }

  if (typeof error === "object" && error !== null && "response" in error) {
    const anyError = error as { response?: { data?: unknown } };
    const data = anyError.response?.data;

    if (data && typeof data === "object") {
      const detail = (data as { detail?: unknown }).detail;
      if (typeof detail === "string") {
        message = detail;
      } else if (Array.isArray(detail)) {
        message = detail.map((item) => (typeof item === "string" ? item : JSON.stringify(item))).join("; ");
      } else if (detail && typeof detail === "object") {
        message = JSON.stringify(detail);
      } else {
        message = JSON.stringify(data);
      }
    }
  } else if (error instanceof Error) {
    message = error.message;
  }

  return message;
}

export function formatApiError(error: unknown): string {
  return getApiErrorMessage(error);
}