package android.support.v4.p012g;

import java.util.Iterator;
import java.util.Map.Entry;

/* renamed from: android.support.v4.g.l */
final class C0118l implements Iterator, Entry {
    int f403a;
    int f404b;
    boolean f405c;
    final /* synthetic */ C0108h f406d;

    C0118l(C0108h c0108h) {
        this.f406d = c0108h;
        this.f405c = false;
        this.f403a = c0108h.m607a() - 1;
        this.f404b = -1;
    }

    public Entry m655a() {
        this.f404b++;
        this.f405c = true;
        return this;
    }

    public final boolean equals(Object obj) {
        boolean z = true;
        if (!this.f405c) {
            throw new IllegalStateException("This container does not support retaining Map.Entry objects");
        } else if (!(obj instanceof Entry)) {
            return false;
        } else {
            Entry entry = (Entry) obj;
            if (!(C0110c.m633a(entry.getKey(), this.f406d.m609a(this.f404b, 0)) && C0110c.m633a(entry.getValue(), this.f406d.m609a(this.f404b, 1)))) {
                z = false;
            }
            return z;
        }
    }

    public Object getKey() {
        if (this.f405c) {
            return this.f406d.m609a(this.f404b, 0);
        }
        throw new IllegalStateException("This container does not support retaining Map.Entry objects");
    }

    public Object getValue() {
        if (this.f405c) {
            return this.f406d.m609a(this.f404b, 1);
        }
        throw new IllegalStateException("This container does not support retaining Map.Entry objects");
    }

    public boolean hasNext() {
        return this.f404b < this.f403a;
    }

    public final int hashCode() {
        int i = 0;
        if (this.f405c) {
            Object a = this.f406d.m609a(this.f404b, 0);
            Object a2 = this.f406d.m609a(this.f404b, 1);
            int hashCode = a == null ? 0 : a.hashCode();
            if (a2 != null) {
                i = a2.hashCode();
            }
            return i ^ hashCode;
        }
        throw new IllegalStateException("This container does not support retaining Map.Entry objects");
    }

    public /* synthetic */ Object next() {
        return m655a();
    }

    public void remove() {
        if (this.f405c) {
            this.f406d.m611a(this.f404b);
            this.f404b--;
            this.f403a--;
            this.f405c = false;
            return;
        }
        throw new IllegalStateException();
    }

    public Object setValue(Object obj) {
        if (this.f405c) {
            return this.f406d.m610a(this.f404b, obj);
        }
        throw new IllegalStateException("This container does not support retaining Map.Entry objects");
    }

    public final String toString() {
        return getKey() + "=" + getValue();
    }
}
