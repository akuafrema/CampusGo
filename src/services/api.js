// src/services/api.js
import axios from "axios";
import { API_URL, STORAGE_KEYS } from "../utils/constants";

// Create axios instance
const api = axios.create({
  baseURL: API_URL || "http://localhost:8080/api",
  timeout: 30000, // 30 seconds
});

// ============================================
// REQUEST INTERCEPTOR: Add JWT token
// ============================================
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN);
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// ============================================
// RESPONSE INTERCEPTOR: Handle token refresh
// ============================================
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If not a 401 error or already retried, reject
    if (error.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(error);
    }

    // Prevent multiple refresh requests
    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject });
      })
        .then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        })
        .catch((err) => Promise.reject(err));
    }

    originalRequest._retry = true;
    isRefreshing = true;

    try {
      const refreshToken = localStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
      if (!refreshToken) {
        throw new Error("No refresh token available");
      }

      const response = await axios.post(`${api.defaults.baseURL}/auth/refresh`, {
        refreshToken,
      });

      const { token, refreshToken: newRefreshToken } = response.data;

      // Store new tokens
      localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, token);
      localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, newRefreshToken);

      // Process queued requests
      processQueue(null, token);

      // Retry original request with new token
      originalRequest.headers.Authorization = `Bearer ${token}`;
      return api(originalRequest);
    } catch (refreshError) {
      // Refresh failed - clear tokens and redirect to login
      localStorage.removeItem(STORAGE_KEYS.ACCESS_TOKEN);
      localStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
      localStorage.removeItem(STORAGE_KEYS.USER);

      processQueue(refreshError, null);

      // Redirect to login
      window.location.href = "/signin";
      return Promise.reject(refreshError);
    } finally {
      isRefreshing = false;
    }
  }
);

export default api;
