import { useState, useEffect, useCallback, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { getChirps, createChirp, deleteChirp } from '../../services/api/chirps'
import { useAuth } from '../../contexts/AuthContext'
import type { Chirp } from '../../types'
import ChirpCard from './ChirpCard'

const MAX_CHIRP_LENGTH = 140

export default function Feed() {
  const { isAuthenticated } = useAuth()
  const [chirps, setChirps] = useState<Chirp[]>([])
  const [sort, setSort] = useState<'desc' | 'asc'>('desc')
  const [body, setBody] = useState('')
  const [loadError, setLoadError] = useState('')
  const [postError, setPostError] = useState('')
  const [loading, setLoading] = useState(true)
  const [posting, setPosting] = useState(false)

  const fetchChirps = useCallback(async () => {
    setLoadError('')
    try {
      const { data } = await getChirps(sort)
      setChirps(data)
    } catch {
      setLoadError('Could not load chirps. Please try again.')
    } finally {
      setLoading(false)
    }
  }, [sort])

  useEffect(() => {
    setLoading(true)
    fetchChirps()
  }, [fetchChirps])

  const handlePost = async (e: FormEvent) => {
    e.preventDefault()
    if (!body.trim()) return
    setPostError('')
    setPosting(true)
    try {
      const { data } = await createChirp(body.trim())
      // Prepend if descending, append if ascending.
      setChirps((prev) => (sort === 'desc' ? [data, ...prev] : [...prev, data]))
      setBody('')
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ??
        'Could not post chirp.'
      setPostError(msg)
    } finally {
      setPosting(false)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await deleteChirp(id)
      setChirps((prev) => prev.filter((c) => c.id !== id))
    } catch {
      // Silently fail — the button disappears on success anyway.
    }
  }

  const remaining = MAX_CHIRP_LENGTH - body.length

  return (
    <div className="space-y-4">
      {/* Compose box — visible to signed-in users only */}
      {isAuthenticated ? (
        <form
          onSubmit={handlePost}
          className="bg-white border border-gray-100 rounded-2xl px-5 py-4 shadow-sm space-y-3"
        >
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="What's happening?"
            rows={3}
            maxLength={MAX_CHIRP_LENGTH}
            className="w-full resize-none text-sm text-gray-800 placeholder-gray-400 focus:outline-none"
          />
          {postError && <p className="text-xs text-red-500">{postError}</p>}
          <div className="flex items-center justify-between">
            <span className={`text-xs ${remaining < 20 ? 'text-red-400' : 'text-gray-400'}`}>
              {remaining} left
            </span>
            <button
              type="submit"
              disabled={posting || !body.trim() || body.length > MAX_CHIRP_LENGTH}
              className="bg-chirpy-600 text-white text-sm font-semibold px-4 py-1.5 rounded-full hover:bg-chirpy-700 disabled:opacity-40 transition-colors"
            >
              {posting ? 'Chirping…' : 'Chirp'}
            </button>
          </div>
        </form>
      ) : (
        <div className="bg-white border border-gray-100 rounded-2xl px-5 py-4 shadow-sm text-sm text-gray-500">
          <Link to="/login" className="text-chirpy-600 font-medium hover:underline">Sign in</Link>
          {' '}or{' '}
          <Link to="/register" className="text-chirpy-600 font-medium hover:underline">create an account</Link>
          {' '}to join the conversation.
        </div>
      )}

      {/* Sort toggle */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-500">Sort:</span>
        {(['desc', 'asc'] as const).map((s) => (
          <button
            key={s}
            onClick={() => setSort(s)}
            className={`text-xs px-3 py-1 rounded-full transition-colors ${
              sort === s
                ? 'bg-chirpy-600 text-white'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {s === 'desc' ? 'Newest first' : 'Oldest first'}
          </button>
        ))}
      </div>

      {/* Feed */}
      {loading ? (
        <div className="text-center py-10 text-gray-400 text-sm">Loading…</div>
      ) : loadError ? (
        <div className="text-center py-10 text-red-400 text-sm">{loadError}</div>
      ) : chirps.length === 0 ? (
        <div className="text-center py-10 text-gray-400 text-sm">
          No chirps yet. Be the first!
        </div>
      ) : (
        <div className="space-y-3">
          {chirps.map((chirp) => (
            <ChirpCard key={chirp.id} chirp={chirp} onDelete={handleDelete} />
          ))}
        </div>
      )}
    </div>
  )
}
