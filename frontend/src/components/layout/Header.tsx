import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../contexts/AuthContext'
import { revoke } from '../../services/api/auth'

export default function Header() {
  const { user, logout, isAuthenticated } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    const refreshToken = localStorage.getItem('refresh_token')
    if (refreshToken) {
      try {
        await revoke(refreshToken)
      } catch {
        // best-effort revoke — clear local state regardless
      }
    }
    logout()
    navigate('/login')
  }

  return (
    <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
      <div className="max-w-2xl mx-auto px-4 h-14 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold text-lg text-chirpy-600">
          <span className="text-2xl">🐦</span>
          Chirpy
        </Link>

        {isAuthenticated ? (
          <div className="flex items-center gap-4">
            {user?.is_chirpy_red && (
              <span
                title="Chirpy Red subscriber"
                className="text-xs font-semibold text-red-500 bg-red-50 px-2 py-0.5 rounded-full"
              >
                Red
              </span>
            )}
            <Link
              to="/profile"
              className="text-sm text-gray-600 hover:text-chirpy-600 truncate max-w-[160px]"
            >
              {user?.email}
            </Link>
            <button
              onClick={handleLogout}
              className="text-sm text-gray-500 hover:text-red-500 transition-colors"
            >
              Logout
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-3">
            <Link to="/login" className="text-sm text-gray-600 hover:text-chirpy-600">
              Login
            </Link>
            <Link
              to="/register"
              className="text-sm bg-chirpy-600 text-white px-3 py-1.5 rounded-full hover:bg-chirpy-700 transition-colors"
            >
              Sign up
            </Link>
          </div>
        )}
      </div>
    </header>
  )
}
