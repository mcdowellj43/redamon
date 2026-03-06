'use client'

import { GlobalHeader } from '../GlobalHeader'
import { Footer } from '../Footer'
import styles from './AppLayout.module.css'

interface AppLayoutProps {
  children: React.ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className={styles.layout}>
      <GlobalHeader />
      <main className={styles.main}>{children}</main>
      <Footer />
    </div>
  )
}
