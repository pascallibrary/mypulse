'use client';

import Link from 'next/link';
import { motion } from 'framer-motion';
import { Home, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.6 }}
      className='relative min-h-screen p-6 text-center flex items-center justify-center bg-no-repeat bg-center bg-contain sm:bg-cover'
      style={{
        backgroundImage: "url('/illustrations/404 Error-pana.png')",
      }}
    >
      {/* Top Right Navigation */}
      <div className='absolute top-4 right-4 flex gap-3 z-10'>
        <Link
          href='/'
          className='flex items-center px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition'
        >
          <Home className='w-4 h-4 mr-1' />
          Home
        </Link>
        <button
          onClick={() => window.history.back()}
          className='flex items-center px-4 py-2 bg-gray-600 text-white rounded-md text-sm font-medium hover:bg-gray-700 transition'
        >
          <ArrowLeft className='w-4 h-4 mr-1' />
          Back
        </button>
      </div>

    </motion.div>
  );
}