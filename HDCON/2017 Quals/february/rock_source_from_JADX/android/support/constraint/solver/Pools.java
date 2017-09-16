package android.support.constraint.solver;

final class Pools {
    private static final boolean DEBUG = false;

    interface Pool<T> {
        T acquire();

        boolean release(T t);

        void releaseAll(T[] tArr, int i);
    }

    static class SimplePool<T> implements Pool<T> {
        private final Object[] mPool;
        private int mPoolSize;

        SimplePool(int maxPoolSize) {
            if (maxPoolSize <= 0) {
                throw new IllegalArgumentException("The max pool size must be > 0");
            }
            this.mPool = new Object[maxPoolSize];
        }

        public T acquire() {
            if (this.mPoolSize <= 0) {
                return null;
            }
            int lastPooledIndex = this.mPoolSize - 1;
            T instance = this.mPool[lastPooledIndex];
            this.mPool[lastPooledIndex] = null;
            this.mPoolSize--;
            return instance;
        }

        public boolean release(T instance) {
            if (this.mPoolSize >= this.mPool.length) {
                return false;
            }
            this.mPool[this.mPoolSize] = instance;
            this.mPoolSize++;
            return true;
        }

        public void releaseAll(T[] variables, int count) {
            if (count > variables.length) {
                count = variables.length;
            }
            for (int i = 0; i < count; i++) {
                T instance = variables[i];
                if (this.mPoolSize < this.mPool.length) {
                    this.mPool[this.mPoolSize] = instance;
                    this.mPoolSize++;
                }
            }
        }

        private boolean isInPool(T instance) {
            for (int i = 0; i < this.mPoolSize; i++) {
                if (this.mPool[i] == instance) {
                    return true;
                }
            }
            return false;
        }
    }

    private Pools() {
    }
}
