
'use client';

import Link from 'next/link';
import { AlertCircle, RefreshCw, Home } from 'lucide-react';

export default function Error({
        error,
        reset,

} : {
    error: Error & { digest?: string };
    reset: () => void;
})  {
    return (
        <div className='min-h-screen bg-gradient-to-br from-red-50 to-orange-50 flex items-center justify-center p-4'>
           <div className='max-w-md w-full text-center'>
              <div className='mb-8'>
                 <div className='w-20 h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4'>
                    <AlertCircle className="w-10 h-10 text-red-600" />
                 </div>
                 <h1 className='text-3xl font-bold text-gray-800 mb-2'>
                    Oops! something went wrong
                 </h1>
                 <p className='text-gray-600 mb-6'>
                   We encountered an unexpected error. Dont worry, our team has been notified.
                 </p>
              </div>

               {process.env.NODE_ENV === 'development' && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6 text-left">
              <h3 className="font-semibold text-red-800 mb-2">Error Details:</h3>
              <p className="text-sm text-red-700 font-mono">{error.message}</p>
              {error.digest && (
                <p className="text-sm text-red-600 mt-2">Error ID: {error.digest}</p>
              )}
            </div>
          )}
       

            <div className="space-y-4">
          <button
            onClick={reset}
            className="w-full inline-flex items-center justify-center px-6 py-3 bg-red-600 text-white rounded-lg font-semibold hover:bg-red-700 transition-colors duration-200"
          >
            <RefreshCw className="w-5 h-5 mr-2" />
            Try Again
          </button>
          
          <Link
            href="/"
            className="w-full inline-flex items-center justify-center px-6 py-3 bg-gray-600 text-white rounded-lg font-semibold hover:bg-gray-700 transition-colors duration-200"
          >
            <Home className="w-5 h-5 mr-2" />
            Go Home
          </Link>
        </div>

        <div className="mt-8 text-sm text-gray-500">
          <p>Need help? <Link href="/contact" className="text-blue-600 hover:underline">Contact Support</Link></p>
        </div>

           </div>
        </div>
    )
}
