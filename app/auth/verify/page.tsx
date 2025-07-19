"use client";
import { useEffect, useState } from 'react';
import axios from 'axios';
import { useRouter, useSearchParams } from 'next/navigation';

export default function VerifyEmail() {
  const [message, setMessage] = useState('Verifying...');
  const router = useRouter();
  const searchParams = useSearchParams(); 

  useEffect(() => {
    const verify = async () => {
      const token = searchParams.get('token');
      if (!token) {
        setMessage('Invalid verification link');
        return;
      }
      try {
        await axios.get(`http://localhost:5000/api/auth/verify?token=${token}`);
        setMessage('Email verified successfully! Redirecting to login...');
        setTimeout(() => router.push('/auth/login'), 2000);
      } catch (error: any) {
        setMessage(error.response?.data?.message || 'Error verifying email');
      }
    };
    verify();
  }, [searchParams, router]);

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <h1 className="text-2xl font-semibold mb-6">Email Verification</h1>
      <p className="text-sm text-gray-600">{message}</p>
    </div>
  );
}