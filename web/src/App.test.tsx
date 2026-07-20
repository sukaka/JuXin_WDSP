import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from './App'

describe('App', () => {
  it('renders system title', () => {
    render(<App />)
    expect(screen.getByText('九章WEB应用智能防护系统')).toBeInTheDocument()
  })
})
