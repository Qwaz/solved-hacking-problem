package android.support.v7.widget;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.database.DataSetObservable;
import android.support.v4.p010e.C0092a;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* renamed from: android.support.v7.widget.z */
class C0307z extends DataSetObservable {
    private static final String f1601a;
    private static final Object f1602b;
    private static final Map f1603c;
    private final Object f1604d;
    private final List f1605e;
    private final List f1606f;
    private final Context f1607g;
    private final String f1608h;
    private Intent f1609i;
    private ac f1610j;
    private int f1611k;
    private boolean f1612l;
    private boolean f1613m;
    private boolean f1614n;
    private boolean f1615o;
    private ae f1616p;

    static {
        f1601a = C0307z.class.getSimpleName();
        f1602b = new Object();
        f1603c = new HashMap();
    }

    private boolean m2847a(ad adVar) {
        boolean add = this.f1606f.add(adVar);
        if (add) {
            this.f1614n = true;
            m2856i();
            m2851d();
            m2853f();
            notifyChanged();
        }
        return add;
    }

    private void m2851d() {
        if (!this.f1613m) {
            throw new IllegalStateException("No preceding call to #readHistoricalData");
        } else if (this.f1614n) {
            this.f1614n = false;
            if (!TextUtils.isEmpty(this.f1608h)) {
                C0092a.m572a(new af(), new ArrayList(this.f1606f), this.f1608h);
            }
        }
    }

    private void m2852e() {
        int g = m2854g() | m2855h();
        m2856i();
        if (g != 0) {
            m2853f();
            notifyChanged();
        }
    }

    private boolean m2853f() {
        if (this.f1610j == null || this.f1609i == null || this.f1605e.isEmpty() || this.f1606f.isEmpty()) {
            return false;
        }
        this.f1610j.m2459a(this.f1609i, this.f1605e, Collections.unmodifiableList(this.f1606f));
        return true;
    }

    private boolean m2854g() {
        if (!this.f1615o || this.f1609i == null) {
            return false;
        }
        this.f1615o = false;
        this.f1605e.clear();
        List queryIntentActivities = this.f1607g.getPackageManager().queryIntentActivities(this.f1609i, 0);
        int size = queryIntentActivities.size();
        for (int i = 0; i < size; i++) {
            this.f1605e.add(new ab(this, (ResolveInfo) queryIntentActivities.get(i)));
        }
        return true;
    }

    private boolean m2855h() {
        if (!this.f1612l || !this.f1614n || TextUtils.isEmpty(this.f1608h)) {
            return false;
        }
        this.f1612l = false;
        this.f1613m = true;
        m2857j();
        return true;
    }

    private void m2856i() {
        int size = this.f1606f.size() - this.f1611k;
        if (size > 0) {
            this.f1614n = true;
            for (int i = 0; i < size; i++) {
                ad adVar = (ad) this.f1606f.remove(0);
            }
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void m2857j() {
        /*
        r9 = this;
        r8 = 1;
        r0 = r9.f1607g;	 Catch:{ FileNotFoundException -> 0x00d3 }
        r1 = r9.f1608h;	 Catch:{ FileNotFoundException -> 0x00d3 }
        r1 = r0.openFileInput(r1);	 Catch:{ FileNotFoundException -> 0x00d3 }
        r2 = android.util.Xml.newPullParser();	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r0 = "UTF-8";
        r2.setInput(r1, r0);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r0 = 0;
    L_0x0013:
        if (r0 == r8) goto L_0x001d;
    L_0x0015:
        r3 = 2;
        if (r0 == r3) goto L_0x001d;
    L_0x0018:
        r0 = r2.next();	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        goto L_0x0013;
    L_0x001d:
        r0 = "historical-records";
        r3 = r2.getName();	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r0 = r0.equals(r3);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        if (r0 != 0) goto L_0x0052;
    L_0x0029:
        r0 = new org.xmlpull.v1.XmlPullParserException;	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r2 = "Share records file does not start with historical-records tag.";
        r0.<init>(r2);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        throw r0;	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
    L_0x0031:
        r0 = move-exception;
        r2 = f1601a;	 Catch:{ all -> 0x00c8 }
        r3 = new java.lang.StringBuilder;	 Catch:{ all -> 0x00c8 }
        r3.<init>();	 Catch:{ all -> 0x00c8 }
        r4 = "Error reading historical recrod file: ";
        r3 = r3.append(r4);	 Catch:{ all -> 0x00c8 }
        r4 = r9.f1608h;	 Catch:{ all -> 0x00c8 }
        r3 = r3.append(r4);	 Catch:{ all -> 0x00c8 }
        r3 = r3.toString();	 Catch:{ all -> 0x00c8 }
        android.util.Log.e(r2, r3, r0);	 Catch:{ all -> 0x00c8 }
        if (r1 == 0) goto L_0x0051;
    L_0x004e:
        r1.close();	 Catch:{ IOException -> 0x00cf }
    L_0x0051:
        return;
    L_0x0052:
        r0 = r9.f1606f;	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r0.clear();	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
    L_0x0057:
        r3 = r2.next();	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        if (r3 != r8) goto L_0x0065;
    L_0x005d:
        if (r1 == 0) goto L_0x0051;
    L_0x005f:
        r1.close();	 Catch:{ IOException -> 0x0063 }
        goto L_0x0051;
    L_0x0063:
        r0 = move-exception;
        goto L_0x0051;
    L_0x0065:
        r4 = 3;
        if (r3 == r4) goto L_0x0057;
    L_0x0068:
        r4 = 4;
        if (r3 == r4) goto L_0x0057;
    L_0x006b:
        r3 = r2.getName();	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r4 = "historical-record";
        r3 = r4.equals(r3);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        if (r3 != 0) goto L_0x00a2;
    L_0x0077:
        r0 = new org.xmlpull.v1.XmlPullParserException;	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r2 = "Share records file not well-formed.";
        r0.<init>(r2);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        throw r0;	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
    L_0x007f:
        r0 = move-exception;
        r2 = f1601a;	 Catch:{ all -> 0x00c8 }
        r3 = new java.lang.StringBuilder;	 Catch:{ all -> 0x00c8 }
        r3.<init>();	 Catch:{ all -> 0x00c8 }
        r4 = "Error reading historical recrod file: ";
        r3 = r3.append(r4);	 Catch:{ all -> 0x00c8 }
        r4 = r9.f1608h;	 Catch:{ all -> 0x00c8 }
        r3 = r3.append(r4);	 Catch:{ all -> 0x00c8 }
        r3 = r3.toString();	 Catch:{ all -> 0x00c8 }
        android.util.Log.e(r2, r3, r0);	 Catch:{ all -> 0x00c8 }
        if (r1 == 0) goto L_0x0051;
    L_0x009c:
        r1.close();	 Catch:{ IOException -> 0x00a0 }
        goto L_0x0051;
    L_0x00a0:
        r0 = move-exception;
        goto L_0x0051;
    L_0x00a2:
        r3 = 0;
        r4 = "activity";
        r3 = r2.getAttributeValue(r3, r4);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r4 = 0;
        r5 = "time";
        r4 = r2.getAttributeValue(r4, r5);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r4 = java.lang.Long.parseLong(r4);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r6 = 0;
        r7 = "weight";
        r6 = r2.getAttributeValue(r6, r7);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r6 = java.lang.Float.parseFloat(r6);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r7 = new android.support.v7.widget.ad;	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r7.<init>(r3, r4, r6);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        r0.add(r7);	 Catch:{ XmlPullParserException -> 0x0031, IOException -> 0x007f }
        goto L_0x0057;
    L_0x00c8:
        r0 = move-exception;
        if (r1 == 0) goto L_0x00ce;
    L_0x00cb:
        r1.close();	 Catch:{ IOException -> 0x00d1 }
    L_0x00ce:
        throw r0;
    L_0x00cf:
        r0 = move-exception;
        goto L_0x0051;
    L_0x00d1:
        r1 = move-exception;
        goto L_0x00ce;
    L_0x00d3:
        r0 = move-exception;
        goto L_0x0051;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v7.widget.z.j():void");
    }

    public int m2858a() {
        int size;
        synchronized (this.f1604d) {
            m2852e();
            size = this.f1605e.size();
        }
        return size;
    }

    public int m2859a(ResolveInfo resolveInfo) {
        synchronized (this.f1604d) {
            m2852e();
            List list = this.f1605e;
            int size = list.size();
            for (int i = 0; i < size; i++) {
                if (((ab) list.get(i)).f1271a == resolveInfo) {
                    return i;
                }
            }
            return -1;
        }
    }

    public ResolveInfo m2860a(int i) {
        ResolveInfo resolveInfo;
        synchronized (this.f1604d) {
            m2852e();
            resolveInfo = ((ab) this.f1605e.get(i)).f1271a;
        }
        return resolveInfo;
    }

    public Intent m2861b(int i) {
        synchronized (this.f1604d) {
            if (this.f1609i == null) {
                return null;
            }
            m2852e();
            ab abVar = (ab) this.f1605e.get(i);
            ComponentName componentName = new ComponentName(abVar.f1271a.activityInfo.packageName, abVar.f1271a.activityInfo.name);
            Intent intent = new Intent(this.f1609i);
            intent.setComponent(componentName);
            if (this.f1616p != null) {
                if (this.f1616p.m2460a(this, new Intent(intent))) {
                    return null;
                }
            }
            m2847a(new ad(componentName, System.currentTimeMillis(), 1.0f));
            return intent;
        }
    }

    public ResolveInfo m2862b() {
        synchronized (this.f1604d) {
            m2852e();
            if (this.f1605e.isEmpty()) {
                return null;
            }
            ResolveInfo resolveInfo = ((ab) this.f1605e.get(0)).f1271a;
            return resolveInfo;
        }
    }

    public void m2863c(int i) {
        synchronized (this.f1604d) {
            m2852e();
            ab abVar = (ab) this.f1605e.get(i);
            ab abVar2 = (ab) this.f1605e.get(0);
            m2847a(new ad(new ComponentName(abVar.f1271a.activityInfo.packageName, abVar.f1271a.activityInfo.name), System.currentTimeMillis(), abVar2 != null ? (abVar2.f1272b - abVar.f1272b) + 5.0f : 1.0f));
        }
    }
}
