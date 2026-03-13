export interface User {
  id: string
  email: string
  created_at: string
  updated_at: string
  is_chirpy_red: boolean
}

export interface Chirp {
  id: string
  body: string
  user_id: string
  created_at: string
  updated_at: string
}

export interface LoginResponse extends User {
  token: string
  refresh_token: string
}
