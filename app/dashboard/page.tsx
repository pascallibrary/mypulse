'use client'

import { useState, useEffect } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { motion, AnimatePresence } from 'framer-motion';

import { useRouter } from 'next/navigation';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';

// Mock interaction logs (replace with API call)
const mockLogs = [
  { id: 1, action: 'Liked quote #123', timestamp: '2025-07-12 10:30 AM' },
  { id: 2, action: 'Created quote #456', timestamp: '2025-07-12 9:15 AM' },
  { id: 3, action: 'Shared quote #789', timestamp: '2025-07-11 3:20 PM' },
];

// Mock user data (replace with auth system)
const user = { 
  name: 'John Doe',
  avatar: '/images/placeholder-avatar.png',
};

// Mock quotes for user (replace with API call)
const initialQuotes = [
  { id: 1, text: 'Keep pushing forward!', author: 'John Doe', userId: 1 },
  { id: 2, text: 'Dream big, work hard.', author: 'Anonymous', userId: 1 },
];

export default function DashboardPage() {
  const [logs, setLogs] = useState(mockLogs);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [quotes, setQuotes] = useState(initialQuotes);
  const [quoteText, setQuoteText] = useState('');
  const [quoteAuthor, setQuoteAuthor] = useState('');
  const [editingQuoteId, setEditingQuoteId] = useState<number | null>(null);
  const [error, setError] = useState('');
  const router = useRouter();

  // Mock stats (replace with API call)
  const stats = {
    quotesCreated: quotes.length,
    quotesLiked: 127,
    quotesShared: 19,
  };

  // Mock featured quotes for carousel (replace with API call)
  const featuredQuotes = [
    { id: 1, text: 'Be the change you wish to see in the world.', author: 'Mahatma Gandhi' },
    { id: 2, text: 'Love is patient, love is kind.', author: '1 Corinthians 13:4' },
    { id: 3, text: 'The only limit to our realization of tomorrow is our doubts of today.', author: 'Franklin D. Roosevelt' },
  ];

  // Auto-scroll for carousel
  useEffect(() => {
    const interval = setInterval(() => {
      setLogs((prev) => [...prev.slice(1), prev[0]]); // Rotate logs for demo
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  // Fetch user quotes (replace with real API call)
  useEffect(() => {
    const fetchQuotes = async () => {
      try {
        const response = await fetch('/api/quotes?userId=1'); // Adjust userId dynamically
        if (response.ok) setQuotes(await response.json());
      } catch (err) {
        console.error('Failed to fetch quotes');
      }
    };
    fetchQuotes();
  }, []);

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/auth/login');
  };

  const handleQuoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!quoteText.trim()) {
      setError('Quote text is required');
      return;
    }

    try {
      if (editingQuoteId) {
        // Update quote
        const response = await fetch(`/api/quotes/${editingQuoteId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: quoteText, author: quoteAuthor || user.name }),
        });
        if (response.ok) {
          const updatedQuote = await response.json();
          setQuotes(quotes.map((q) => (q.id === editingQuoteId ? updatedQuote : q)));
          setEditingQuoteId(null);
        } else {
          throw new Error('Failed to update quote');
        }
      } else {
        // Create quote
        const response = await fetch('/api/quotes', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: quoteText, author: quoteAuthor || user.name, userId: 1 }),
        });
        if (response.ok) {
          const newQuote = await response.json();
          setQuotes([...quotes, newQuote]);
        } else {
          throw new Error('Failed to create quote');
        }
      }
      setQuoteText('');
      setQuoteAuthor('');
    } catch (err) {
      setError('Failed to save quote');
    }
  };

  const handleEditQuote = (quote: typeof initialQuotes[0]) => {
    setQuoteText(quote.text);
    setQuoteAuthor(quote.author);
    setEditingQuoteId(quote.id);
  };

  const handleDeleteQuote = async (id: number) => {
    try {
      const response = await fetch(`/api/quotes/${id}`, {
        method: 'DELETE',
      });
      if (response.ok) {
        setQuotes(quotes.filter((q) => q.id !== id));
      } else {
        throw new Error('Failed to delete quote');
      }
    } catch (err) {
      setError('Failed to delete quote');
    }
  };

  return (
    <main className="relative min-h-screen bg-gradient-to-br from-indigo-900 via-black to-gray-900 text-white flex p-6 overflow-hidden">
      {/* Animated Background Grid */}
      <div className="absolute top-0 left-0 w-full h-full bg-[url('/grid.svg')] opacity-10 z-0" />

      {/* Falling Stars Overlay */}
      <div className="absolute top-0 left-0 w-full h-full z-0 pointer-events-none animate-fadeIn">
        <div className="w-full h-full bg-[url('/stars.gif')] opacity-10"></div>
      </div>

      {/* Sidebar */}
      <motion.aside
        className="fixed top-0 left-0 h-full w-64 bg-gray-800/50 p-6 z-20 flex flex-col space-y-6"
        initial={{ x: -300 }}
        animate={{ x: 0 }}
        transition={{ duration: 0.8 }}
      >
        <h2 className="text-2xl font-bold font-mono text-shadow-neon text-indigo-400">Activity Log</h2>
        <div className="flex-1 overflow-y-auto space-y-4">
          <AnimatePresence>
            {logs.map((log) => (
              <motion.div
                key={log.id}
                className="p-4 bg-gray-700/30 rounded-lg text-sm"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.5 }}
              >
                <p>{log.action}</p>
                <p className="text-gray-400">{log.timestamp}</p>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </motion.aside>

      {/* Main Content */}
      <div className="relative z-10 ml-64 flex-1 max-w-6xl mx-auto space-y-8">
        {/* Header with Profile Avatar */}
        <header className="flex justify-between items-center">
          <motion.h1
            className="text-3xl md:text-4xl font-bold font-mono text-shadow-neon text-indigo-400"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5, duration: 1 }}
          >
            Welcome Back, {user.name}
          </motion.h1>
          <div className="relative">
            <motion.div
              className="cursor-pointer"
              onClick={() => setIsProfileOpen(!isProfileOpen)}
              whileHover={{ scale: 1.1 }}
              transition={{ duration: 0.3 }}
            >
              <Image
                src={user.avatar}
                alt="User Avatar"
                width={48}
                height={48}
                className="rounded-full border-2 border-indigo-400"
              />
            </motion.div>
            {isProfileOpen && (
              <motion.div
                className="absolute right-0 mt-2 w-48 bg-gray-800/80 p-4 rounded-lg shadow-lg"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.3 }}
              >
                <Link href="/settings" className="block py-2 text-indigo-400 hover:underline">
                  Settings
                </Link>
                <button
                  onClick={handleLogout}
                  className="w-full text-left py-2 text-red-400 hover:underline"
                >
                  Logout
                </button>
              </motion.div>
            )}
          </div>
        </header>

        {/* Main Dashboard Content */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* Animated Quote Carousel */}
          <motion.div
            className="bg-gray-800/50 p-6 rounded-lg"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7, duration: 1 }}
          >
            <h2 className="text-2xl font-bold font-mono text-shadow-neon text-indigo-400 mb-4">
              Featured Quotes
            </h2>
            <motion.div
              className="flex space-x-4 overflow-x-auto"
              animate={{ x: [0, -200] }}
              transition={{ repeat: Infinity, duration: 10, ease: 'linear' }}
              whileHover={{ animationPlayState: 'paused' }}
            >
              {featuredQuotes.map((quote) => (
                <div
                  key={quote.id}
                  className="min-w-[300px] p-4 bg-gray-700/30 rounded-lg transform hover:scale-105 transition-transform"
                  style={{ perspective: '1000px' }}
                >
                  <motion.div
                    className="p-4 bg-gray-900/50 rounded-lg"
                    whileHover={{ rotateY: 10, rotateX: 10 }}
                    transition={{ duration: 0.3 }}
                  >
                    <p className="text-gray-200 italic">"{quote.text}"</p>
                    <p className="text-indigo-400 text-right mt-2">— {quote.author}</p>
                  </motion.div>
                </div>
              ))}
            </motion.div>
          </motion.div>

          {/* Live Stats Widget */}
          <motion.div
            className="bg-gray-800/50 p-6 rounded-lg"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.9, duration: 1 }}
          >
            <h2 className="text-2xl font-bold font-mono text-shadow-neon text-indigo-400 mb-4">
              Your Stats
            </h2>
            <div className="grid grid-cols-3 gap-4 text-center">
              <motion.div
                className="p-4 bg-gray-700/30 rounded-lg"
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ duration: 1, repeat: Infinity, repeatType: 'reverse' }}
              >
                <p className="text-3xl font-bold text-indigo-400">{stats.quotesCreated}</p>
                <p className="text-gray-300">Quotes Created</p>
              </motion.div>
              <motion.div
                className="p-4 bg-gray-700/30 rounded-lg"
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ duration: 1, repeat: Infinity, repeatType: 'reverse', delay: 0.2 }}
              >
                <p className="text-3xl font-bold text-indigo-400">{stats.quotesLiked}</p>
                <p className="text-gray-300">Quotes Liked</p>
              </motion.div>
              <motion.div
                className="p-4 bg-gray-700/30 rounded-lg"
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ duration: 1, repeat: Infinity, repeatType: 'reverse', delay: 0.4 }}
              >
                <p className="text-3xl font-bold text-indigo-400">{stats.quotesShared}</p>
                <p className="text-gray-300">Quotes Shared</p>
              </motion.div>
            </div>
          </motion.div>
        </div>

        {/* 3D Quote Card */}
        <motion.div
          className="bg-gray-800/50 p-6 rounded-lg"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.1, duration: 1 }}
        >
          <h2 className="text-2xl font-bold font-mono text-shadow-neon text-indigo-400 mb-4">
            Quote of the Day
          </h2>
          <motion.div
            className="p-6 bg-gray-900/50 rounded-lg"
            whileHover={{ rotateY: 15, rotateX: 15, scale: 1.05 }}
            transition={{ duration: 0.3 }}
            style={{ perspective: '1000px' }}
          >
            <p className="text-gray-200 italic">
              "The only way to do great work is to love what you do."
            </p>
            <p className="text-indigo-400 text-right mt-2">— Steve Jobs</p>
            <div className="flex justify-end space-x-2 mt-4">
              <Button className="px-4 py-2 bg-purple-600 hover:bg-purple-700">
                ❤️ Like
              </Button>
              <Button className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700">
                🔗 Share
              </Button>
            </div>
          </motion.div>
        </motion.div>

        {/* Your Quotes Section */}
        <motion.div
          className="bg-gray-800/50 p-6 rounded-lg"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.3, duration: 1 }}
        >
          <h2 className="text-2xl font-bold font-mono text-shadow-neon text-indigo-400 mb-4">
            Your Quotes
          </h2>
          {/* Quote Form */}
          <form onSubmit={handleQuoteSubmit} className="space-y-4 mb-6">
            <Input
              placeholder="Enter your quote"
              value={quoteText}
              onChange={(e) => setQuoteText(e.target.value)}
              className="w-full"
            />
            <Input
              placeholder="Author (optional)"
              value={quoteAuthor}
              onChange={(e) => setQuoteAuthor(e.target.value)}
              className="w-full"
            />
            {error && (
              <motion.p
                className="text-red-400 text-center"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
              >
                {error}
              </motion.p>
            )}
            <Button
              type="submit"
              className="w-full px-6 py-3 bg-purple-600 hover:bg-purple-700"
            >
              {editingQuoteId ? 'Update Quote' : 'Add Quote'} 🎨
            </Button>
          </form>
          {/* Quote List */}
          <div className="space-y-4">
            <AnimatePresence>
              {quotes.map((quote) => (
                <motion.div
                  key={quote.id}
                  className="p-4 bg-gray-700/30 rounded-lg flex justify-between items-center"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.5 }}
                >
                  <div>
                    <p className="text-gray-200 italic">"{quote.text}"</p>
                    <p className="text-indigo-400 text-sm">— {quote.author}</p>
                  </div>
                  <div className="flex space-x-2">
                    <Button
                      onClick={() => handleEditQuote(quote)}
                      className="px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-sm"
                    >
                      ✏️ Edit
                    </Button>
                    <Button
                      onClick={() => handleDeleteQuote(quote.id)}
                      className="px-3 py-1 bg-red-600 hover:bg-red-700 text-sm"
                    >
                      🗑️ Delete
                    </Button>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </motion.div>
      </div>
    </main>
  );
}