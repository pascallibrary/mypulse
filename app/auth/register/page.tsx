"use client";
import { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/navigation';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { FaEye, FaEyeSlash } from 'react-icons/fa';

export default function Signup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('');
  const [message, setMessage] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const router = useRouter();

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await axios.post(`http://localhost:5000/api/auth/register`, { username, email, password });
      setMessage('Registration successful! Please check your email to verify.');
    } catch (error: any) {
      setMessage(error.response?.data?.message || 'Error registering');
    }
  };

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <h1 className="text-2xl font-semibold mb-6">Sign Up</h1>
      <form onSubmit={handleSignup} className="flex flex-col gap-3 w-full max-w-xs sm:max-w-sm">
        <Input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Username"
        />
        <Input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
        />
        <div className="relative">
          <Input
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
          />
          <button
            type="button"
            className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-500"
            onClick={() => setShowPassword(!showPassword)}
          >
            {showPassword ? <FaEyeSlash /> : <FaEye />}
          </button>
        </div>

        <Button type="submit">Sign Up</Button>
      </form>
      {message && <p className="mt-4 text-sm text-gray-600">{message}</p>}
      <p className="mt-4 text-sm">
        Already have an account?{' '}
        <a href="/auth/login" className="text-blue-500 hover:underline">Login</a>
      </p>
      <p className="mt-2 text-sm">
       <a href="/" className="text-blue-500 hover:underline">Back to Home</a>
     </p>
    </div>
  );
}