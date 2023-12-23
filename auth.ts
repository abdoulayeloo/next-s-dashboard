import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

/**
 * Retrieves a user based on their email address.
 *
 * @param {string} email - The email address of the user.
 * @return {Promise<User | undefined>} A promise that resolves to the user object if found, or undefined if not found.
 */
async function getUser(email: string): Promise<User | undefined> {
    try {
      const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
      return user.rows[0];
    } catch (error) {
      console.error('Failed to fetch user:', error);
      throw new Error('Failed to fetch user.');
    }
  }

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
        /**
         * Authorizes a user with the given credentials.
         *
         * @param {Object} credentials - The user's credentials.
         *     - {string} email - The user's email address.
         *     - {string} password - The user's password (minimum 6 characters).
         * @return {Promise<Object|null>} - A promise that resolves to the user object if
         *     the credentials are valid, or null otherwise.
         */
        async authorize(credentials) {
          const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);
            if (parsedCredentials.success) {
                const { email, password } = parsedCredentials.data;
                const user = await getUser(email);
                if (!user) return null; 
                const passwordsMatch = await bcrypt.compare(password, user.password);
                if (passwordsMatch) return user;
            }
            console.log('Invalid credentials');
            return null;
        },
      }),
  ],
});
