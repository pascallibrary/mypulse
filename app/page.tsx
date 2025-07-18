'use client'

import Link from 'next/link';
import Image from 'next/image';
import { motion } from 'framer-motion';

export default function Home() {
    return (
        <main className='relative min-h-screen bg-gradient-to-br from-indigo-900 via-black to-gray-900 text-white flex items-center justify-center p-6 overflow-hidden'>

            {/* Main Content */}
            <div className='relative z-20 max-w-6xl w-full flex flex-col md:flex-row items-center justify-between gap-8 mt-40'>

                {/* Text and Buttons */}
                <div className='text-center md:text-left space-y-8 flex-1'>
                    <motion.h1 
                      className='text-4xl md:text-5xl font-bold font-mono text-shadow-neon'
                      initial={{ opacity: 0 }} 
                      animate={{ opacity: 1 }} 
                      transition={{ delay: 1, duration: 1 }}
                    >
                        Welcome to <span className='text-indigo-400'>QuotePulse</span>
                    </motion.h1>

                    <motion.p 
                      className='text-lg md:text-xl text-gray-300 leading-relaxed'
                      initial={{ opacity: 0 }} 
                      animate={{ opacity: 1 }} 
                      transition={{ delay: 1.5, duration: 1 }}
                    >
                        Your daily dose of inspiration - curated from psychology, personal development, the Bible, and more. Delivered straight to your mind, inbox, heart.
                    </motion.p>

                    <motion.div 
                      className='flex flex-col md:flex-row justify-center md:justify-start gap-4'
                      initial={{ opacity: 0 }} 
                      animate={{ opacity: 1 }} 
                      transition={{ delay: 2, duration: 1 }}
                    >
                        <Link href="/auth/login" className='inline-flex items-center justify-center px-6 py-3 bg-purple-600 text-white rounded-lg font-arcade hover:bg-purple-700 transition'>
                            🎮 Sign in 
                        </Link>

                        <Link href="/auth/register" className='inline-flex items-center justify-center px-6 py-3 bg-indigo-600 text-white rounded-lg font-arcade hover:bg-indigo-700 transition'>
                              🎮 Register 
                        </Link>

                        <Link href='/subscribe' className='inline-flex items-center justify-center px-6 py-3 bg-blue-500 text-white rounded-lg font-arcade hover:bg-blue-600 transition'> 
                            📬 Subscribe
                        </Link>
                    </motion.div>
                </div>

                {/* DrawKit Illustration */}
                <motion.div 
                  className='flex-1 flex justify-center'
                  initial={{ opacity: 0, y: 30 }} 
                  animate={{ opacity: 1, y: 0 }} 
                  transition={{ delay: 2.2, duration: 1 }}
                >
                    <Image
                      src="/illustrations/Cheer up-pana.png"
                      alt="animated user interacting"
                      width={400}
                      height={400}
                      className="w-auto h-auto max-w-full"
                      priority
                    />
                </motion.div>
            </div>
        </main>
    );
}