// frontend/src/lib/auth.ts

const TOKEN_KEY = "leetha_token";
const ROLE_KEY = "leetha_role";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getRole(): string | null {
  return localStorage.getItem(ROLE_KEY);
}

export function setAuth(token: string, role: string): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(ROLE_KEY, role);
}

export function clearAuth(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
}

export function isAdmin(): boolean {
  return getRole() === "admin";
}

export function isAuthenticated(): boolean {
  return getToken() !== null;
}
