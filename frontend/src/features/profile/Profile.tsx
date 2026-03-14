import { useState, type FormEvent } from 'react'
import { updateUser } from '../../services/api/auth'
import { useAuth } from '../../contexts/AuthContext'

export default function Profile() {
  const { user, updateUser: setUser } = useAuth()
  const [email, setEmail] = useState(user?.email ?? '')
  const [password, setPassword] = useState('')
  const [success, setSuccess] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setSuccess('')
    setError('')
    setLoading(true)
    try {
      const { data } = await updateUser(email, password)
      setUser(data)
      setPassword('')
      setSuccess('Profile updated.')
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ??
        'Update failed. Please try again.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-sm mx-auto mt-6">
      <h1 className="text-2xl font-bold text-gray-800 mb-6">Profile</h1>

      {user?.is_chirpy_red && (
        <div className="mb-4 text-sm text-red-600 bg-red-50 border border-red-200 rounded-xl px-4 py-2 flex items-center gap-2">
          <span>⭐</span> Chirpy Red subscriber
        </div>
      )}

      <form
        onSubmit={handleSubmit}
        className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-sm border border-chirpy-200 p-6 space-y-4"
      >
        {success && (
          <p className="text-sm text-green-600 bg-green-50 border border-green-200 rounded-lg px-3 py-2">
            {success}
          </p>
        )}
        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
            {error}
          </p>
        )}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-chirpy-500 focus:border-transparent"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            New password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={6}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-chirpy-500 focus:border-transparent"
            placeholder="Enter new password"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-chirpy-600 text-white py-2 rounded-full text-sm font-semibold hover:bg-chirpy-700 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Saving…' : 'Save changes'}
        </button>
      </form>
    </div>
  )
}
