'use client'

import { motion } from 'framer-motion';

export default function Auth({ children } : { children: React.ReactNode}) {
    return (
        <main className='relative min-h-screen bg-gradient-to-br from-indigo-900 via-black-to-gray-900 text-white flex items-center justify-center p-6 overflow-hidden'>
          {/* Main Content */}
      <motion.div
        className="relative z-20 max-w-md w-full bg-gray-800/50 p-8 rounded-lg shadow-lg"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 1 }}
      >
        {children}
      </motion.div>
        </main>
    )
}