export default function Loading () {
    return(
        <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
            <div className="text-center">
              <div className="relative">
                <div className="w-16 h-16 mx-auto mb-4 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin"></div>
                <div className="absolute inset-0 w-12 h-12 mx-auto mt-2 border-4 border-transparent border-t-indigo-400 rounded-full animate-spin animate-reverse"></div>
              </div>
              <h2 className="text-xl font-semibold text-gray-700 nb-2">Loading QuotePulse</h2>
            </div>
        </div>
    )
}