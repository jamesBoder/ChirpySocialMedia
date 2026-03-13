import type { Chirp } from '../../types'
import { useAuth } from '../../contexts/AuthContext'

interface Props {
  chirp: Chirp
  onDelete: (id: string) => void
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function abbreviateId(id: string): string {
  return id.slice(0, 8)
}

export default function ChirpCard({ chirp, onDelete }: Props) {
  const { user } = useAuth()
  const isOwner = user?.id === chirp.user_id

  return (
    <article className="bg-white border border-gray-100 rounded-2xl px-5 py-4 shadow-sm hover:shadow transition-shadow">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-gray-800 text-sm leading-relaxed whitespace-pre-wrap break-words">
            {chirp.body}
          </p>
        </div>
        {isOwner && (
          <button
            onClick={() => onDelete(chirp.id)}
            aria-label="Delete chirp"
            className="flex-shrink-0 text-gray-300 hover:text-red-400 transition-colors text-lg leading-none"
          >
            ×
          </button>
        )}
      </div>
      <div className="mt-3 flex items-center gap-2 text-xs text-gray-400">
        <span title={chirp.user_id}>@{abbreviateId(chirp.user_id)}</span>
        <span>·</span>
        <time dateTime={chirp.created_at}>{formatDate(chirp.created_at)}</time>
      </div>
    </article>
  )
}
