"use client";
import { useState, useEffect } from 'react';
import axios from 'axios';
import { useRouter, useSearchParams } from 'next/navigation';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

export default function ResetPassword() {
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');
  const [token, setToken] = useState('');
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const tokenParam = searchParams.get('token');
    if (tokenParam) setToken(tokenParam);
  }, [searchParams]);

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:5000/auth/reset-password', { token, newPassword });
      setMessage('Password reset successfully! Redirecting to login...');
      setTimeout(() => router.push('/auth/login'), 2000);
    } catch (error: any) {
      setMessage(error.response?.data?.message || 'Error resetting password');
    }
  };

  const handleRequestReset = async (e: React.FormEvent) => {
    e.preventDefault();
    const email = (e.target as any).email.value;
    try {
      await axios.post('http://localhost:5000/auth/request-password-reset', { email });
      setMessage('Password reset link sent to your email.');
    } catch (error: any) {
      setMessage(error.response?.data?.message || 'Error requesting reset');
    }
  };

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <h1 className="text-2xl font-semibold mb-6">Reset Password</h1>
      {token ? (
        <form onSubmit={handleResetPassword} className="flex flex-col gap-3 w-full max-w-xs sm:max-w-sm">
          <Input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="New Password"
          />
          <Button type="submit">Reset Password</Button>
        </form>
      ) : (
        <form onSubmit={handleRequestReset} className="flex flex-col gap-3 w-full max-w-xs sm:max-w-sm">
          <Input
            type="email"
            name="email"
            placeholder="Enter your email"
          />
          <Button type="submit">Send Reset Link</Button>
        </form>
      )}
      {message && <p className="mt-4 text-sm text-gray-600">{message}</p>}
    </div>
  );
}