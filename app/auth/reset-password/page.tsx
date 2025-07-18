'use client'

import { useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Input } from '../../../components/ui/Input';
import { Button } from '../../../components/ui/Button';



export default function ResetPasswordPage() {
       const [email, setEmail] = useState('');
       const [message, setMessage] = useState('');
       const [error, setError] = useState('');

       const handleSubmit = async (e: React.FormEvent) => {
          e.preventDefault();
          setError('');
          setMessage('');

          try {
            const response = await fetch('/api/auth/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
            });

            if(!response.ok) throw new Error('Failed to send reset link');
            setMessage('Password reset link sent to your email')
          } catch(err) {
            console.error(err);
            setError('Failed to send reset link. Please try again.')
          }
       };

       return (
        <div className='space-y-6'>
            <motion.h1
              className='text-3xl font-bold font-mono text-shadow-neon text-center text-indigo-400'
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition= {{ delay: 0.5, duration:1 }}
            >
               Reset Password 
            </motion.h1>

            <form onSubmit={handleSubmit} className='space-y-4'>
                <div>
                    <Input 
                      type='email'
                      placeholder='Enter your email'
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className='w-full px-4 py-3 bg-gray-700/50 text-white rounded-lg focus:ring-2 focus:ring-indigo-400'
                      required 
                    />
                </div>

                {error && (
                    <motion.p 
                    className='text-red-400 text-center'
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.5 }}
                    >
                      {error}
                    </motion.p>
                )}

                {message && (
                    <motion.p
                     className='text-green-400 text-center'
                     initial={{ opacity: 0 }}
                     animate={{ opacity: 1 }}
                     transition={{ duration: 0.5 }}
                    >
                      {message}
                    </motion.p>
                )}

                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.7, duration: 1 }}
                >
                <Button 
                type="submit"
                className='w-full px-6 py-3 bg-purple-600 text-white rounded-lg font-arcade'
                >
                     📧 Send Reset Link
                </Button>   
                </motion.div>
            </form>
             <motion.div
        className="text-center space-y-2"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.9, duration: 1 }}
      >
        <p className="text-gray-300">
          Remember your password?{' '}
          <Link href="/auth/login" className="text-indigo-400 hover:underline">
            Login
          </Link>
        </p>
        <p>
          <Link href="/" className="text-indigo-400 hover:underline">
            Back to Home
          </Link>
        </p>
      </motion.div>
        </div>
       )


}