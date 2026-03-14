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
    <header className="bg-gradient-to-r from-chirpy-600 to-indigo-600 sticky top-0 z-10 shadow-md">
      <div className="max-w-2xl mx-auto px-4 h-14 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold text-lg text-white">
          <span className="text-2xl">🐦</span>
          Chirpy
        </Link>

        {isAuthenticated ? (
          <div className="flex items-center gap-4">
            {user?.is_chirpy_red && (
              <span
                title="Chirpy Red subscriber"
                className="text-xs font-semibold text-red-200 bg-red-500 px-2 py-0.5 rounded-full"
              >
                Red
              </span>
            )}
            <Link
              to="/profile"
              className="text-sm text-chirpy-100 hover:text-white truncate max-w-[160px] transition-colors"
            >
              {user?.email}
            </Link>
            <button
              onClick={handleLogout}
              className="text-sm text-chirpy-200 hover:text-white transition-colors"
            >
              Logout
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-3">
            <Link to="/login" className="text-sm text-chirpy-100 hover:text-white transition-colors">
              Login
            </Link>
            <Link
              to="/register"
              className="text-sm bg-white text-chirpy-600 px-3 py-1.5 rounded-full hover:bg-chirpy-50 font-semibold transition-colors"
            >
              Sign up
            </Link>
          </div>
        )}
      </div>
    </header>
  )
}
