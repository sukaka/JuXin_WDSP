import { useEffect, useRef, useState } from 'react'

/** 数字滚动动画：值变化时从旧值缓动过渡到新值 */
export default function CountUp({
  value,
  duration = 900,
  formatter,
}: {
  value: number
  duration?: number
  formatter?: (v: number) => string
}) {
  const [display, setDisplay] = useState(value)
  const prevRef = useRef(value)

  useEffect(() => {
    const from = prevRef.current
    const to = value
    prevRef.current = to
    if (from === to) {
      setDisplay(to)
      return
    }
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - p, 3)
      setDisplay(from + (to - from) * eased)
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value, duration])

  return <>{formatter ? formatter(display) : Math.round(display).toLocaleString()}</>
}
