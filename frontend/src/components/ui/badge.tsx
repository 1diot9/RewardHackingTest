import { mergeProps } from '@base-ui/react/merge-props'
import { useRender } from '@base-ui/react/use-render'
import { cva, type VariantProps } from 'class-variance-authority'

import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex h-5 w-fit shrink-0 items-center justify-center rounded-4xl border border-transparent px-2 text-xs font-medium whitespace-nowrap',
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground',
        secondary: 'bg-secondary text-secondary-foreground',
        destructive: 'bg-destructive/10 text-destructive',
        outline: 'border-border text-foreground',
        success: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/20',
        warning: 'bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/20',
        info: 'bg-blue-500/15 text-blue-200 ring-1 ring-blue-500/20',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

function Badge({
  className,
  variant = 'default',
  render,
  ...props
}: useRender.ComponentProps<'span'> & VariantProps<typeof badgeVariants>) {
  return useRender({
    defaultTagName: 'span',
    props: mergeProps<'span'>({ className: cn(badgeVariants({ variant }), className) }, props),
    render,
    state: { slot: 'badge', variant },
  })
}

export { Badge, badgeVariants }
