'use client';
import { cn } from '@/lib/utils';

interface LoadingSkeletonProps {
  className?: string;
  count?: number;
}

export function SkeletonBlock({ className }: { className?: string }) {
  return <div className={cn('skeleton', className)} />;
}

export function ScanCardSkeleton() {
  return (
    <div className="glass-card p-5 space-y-3">
      <div className="flex items-center justify-between">
        <SkeletonBlock className="h-4 w-48" />
        <SkeletonBlock className="h-6 w-16 rounded-full" />
      </div>
      <SkeletonBlock className="h-3 w-32" />
      <div className="flex gap-3">
        <SkeletonBlock className="h-8 w-20 rounded-lg" />
        <SkeletonBlock className="h-8 w-20 rounded-lg" />
      </div>
    </div>
  );
}

export function ReportSkeleton() {
  return (
    <div className="space-y-6">
      <div className="glass-card p-8 flex gap-8">
        <SkeletonBlock className="w-32 h-32 rounded-full" />
        <div className="flex-1 space-y-3">
          <SkeletonBlock className="h-6 w-64" />
          <SkeletonBlock className="h-4 w-full" />
          <SkeletonBlock className="h-4 w-3/4" />
        </div>
      </div>
      {[1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="glass-card p-5 flex gap-4 items-start">
          <SkeletonBlock className="h-6 w-16 rounded-full flex-shrink-0" />
          <div className="flex-1 space-y-2">
            <SkeletonBlock className="h-4 w-3/4" />
            <SkeletonBlock className="h-3 w-full" />
            <SkeletonBlock className="h-3 w-1/2" />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function LoadingSkeleton({ className, count = 3 }: LoadingSkeletonProps) {
  return (
    <div className={cn('space-y-4', className)}>
      {Array.from({ length: count }).map((_, i) => (
        <ScanCardSkeleton key={i} />
      ))}
    </div>
  );
}
