package android.support.v4.p012g;

import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/* renamed from: android.support.v4.g.a */
public class C0107a extends C0106n implements Map {
    C0108h f373a;

    public C0107a(int i) {
        super(i);
    }

    private C0108h m601b() {
        if (this.f373a == null) {
            this.f373a = new C0109b(this);
        }
        return this.f373a;
    }

    public boolean m602a(Collection collection) {
        return C0108h.m606c(this, collection);
    }

    public Set entrySet() {
        return m601b().m618d();
    }

    public Set keySet() {
        return m601b().m619e();
    }

    public void putAll(Map map) {
        m596a(this.h + map.size());
        for (Entry entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    public Collection values() {
        return m601b().m620f();
    }
}
