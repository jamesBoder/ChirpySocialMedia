import api from './client'
import type { User, LoginResponse } from '../../types'

export const register = (email: string, password: string) =>
  api.post<User>('/api/users', { email, password })

export const login = (email: string, password: string) =>
  api.post<LoginResponse>('/api/login', { email, password })

export const revoke = (refreshToken: string) =>
  api.post('/api/revoke', null, {
    headers: { Authorization: `Bearer ${refreshToken}` },
  })

export const updateUser = (email: string, password: string) =>
  api.put<User>('/api/users', { email, password })
