"use client";
import { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/navigation';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/auth/login', { email, password });
      localStorage.setItem('token', response.data.token);
      router.push(response.data.redirect);
    } catch (error: any) {
      setMessage(error.response?.data?.message || 'Error logging in');
    }
  };

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <h1 className="text-2xl font-semibold mb-6">Login</h1>
      <form onSubmit={handleLogin} className="flex flex-col gap-3 w-full max-w-xs sm:max-w-sm">
        <Input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
        />
        <Input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
        />
        <Button type="submit">Login</Button>
      </form>
      {message && <p className="mt-4 text-sm text-gray-600">{message}</p>}
      <p className="mt-4 text-sm">
        Forgot password?{' '}
        <a href="/auth/reset-password" className="text-blue-500 hover:underline">Reset Password</a>
      </p>
      <p className="mt-2 text-sm">
        No account?{' '}
        <a href="/auth/register" className="text-blue-500 hover:underline">Sign Up</a>
      </p>
    </div>
  );
}