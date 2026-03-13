import api from './client'
import type { Chirp } from '../../types'

export const getChirps = (sort: 'asc' | 'desc' = 'desc', authorId?: string) => {
  const params = new URLSearchParams({ sort })
  if (authorId) params.set('author_id', authorId)
  return api.get<Chirp[]>(`/api/chirps?${params}`)
}

export const createChirp = (body: string) =>
  api.post<Chirp>('/api/chirps', { body })

export const deleteChirp = (id: string) =>
  api.delete(`/api/chirps/${id}`)
