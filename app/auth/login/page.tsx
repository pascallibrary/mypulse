'use client'

import { SetStateAction, useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Input } from '../../../components/ui/Input';
import { Button } from '../../../components/ui/Button';



export default function Login() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const [error, setError] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        try {
            const response = await fetch('http://localhost:5000/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });

            if (!response.ok) throw new Error('Login failed');
            // Handle successful login 

            window.location.href = '/dashboard';

        } catch (err) {
            console.error(err);
            setError('Invalid credentials');
        }
    };

    return (
        <div className='space-y-6'>
           <motion.h1
           className='text-3xl font-bold font-momo text-shadow-neon text-center text-indigo-400'
           initial={{ opacity: 0 }}
           animate={{ opacity: 1 }}
           transition={{ delay: 0.5, duration: 1 }}
 >
           Login to QuotePulse  
        </motion.h1>

        <form onSubmit={handleSubmit} className='space-y-4'>
           <div>
             <Input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e: { target: { value: SetStateAction<string>; }; }) => setEmail(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700/50 text-white rounded-lg focus:ring-2 focus:ring-indigo-400"
              required
          />
           </div>

           <div>
             <Input 
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e: { target: { value: SetStateAction<string>; }; }) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700/50 text-white rounded-lg focus:ring-2 focus:ring-indigo-400"
              required 
             />
           </div>

        {error && (
            <motion.p
            className='text-red-400 text-center'
            initial={{ opacity: 0 }} 
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
        > {error}               
        </motion.p>       
        )}

        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition= {{ delay: 0.7, duration: 1 }}
        >
            <Button
              type="submit"
              className="w-full px-6 py-3 bg-purple-600 text-white rounded-lg font-arcade hover:bg-purple-700 transition"
            >
            🎮 Login
            </Button>
        </motion.div>

       <motion.div
        className='text-center space-y-2'
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.9, duration:1 }}
       > 
       <p className='text-gray-300'>
           Don&apos;t have an account?{' '}
           <Link href='/auth/register' className='text-indigo-400 hover:underline'>
            Sign up 
           </Link>
       </p>

       <p>
        <Link href='/' className='text-indigo-400 hover:underline'>
            Back to Home 
        </Link>
       </p>

       </motion.div>
        </form>
        </div>
    )
}