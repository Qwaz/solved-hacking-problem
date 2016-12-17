package android.support.v4.p003a;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.v4.p002b.C0020a;
import android.util.Log;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: android.support.v4.a.bk */
public final class bk implements Iterable {
    private static final bm f199a;
    private final ArrayList f200b;
    private final Context f201c;

    static {
        if (VERSION.SDK_INT >= 11) {
            f199a = new bo();
        } else {
            f199a = new bn();
        }
    }

    private bk(Context context) {
        this.f200b = new ArrayList();
        this.f201c = context;
    }

    public static bk m283a(Context context) {
        return new bk(context);
    }

    public bk m284a(Activity activity) {
        Intent intent = null;
        if (activity instanceof bl) {
            intent = ((bl) activity).m289a();
        }
        Intent a = intent == null ? bc.m256a(activity) : intent;
        if (a != null) {
            ComponentName component = a.getComponent();
            if (component == null) {
                component = a.resolveActivity(this.f201c.getPackageManager());
            }
            m285a(component);
            m286a(a);
        }
        return this;
    }

    public bk m285a(ComponentName componentName) {
        int size = this.f200b.size();
        try {
            Intent a = bc.m257a(this.f201c, componentName);
            while (a != null) {
                this.f200b.add(size, a);
                a = bc.m257a(this.f201c, a.getComponent());
            }
            return this;
        } catch (Throwable e) {
            Log.e("TaskStackBuilder", "Bad ComponentName while traversing activity parent metadata");
            throw new IllegalArgumentException(e);
        }
    }

    public bk m286a(Intent intent) {
        this.f200b.add(intent);
        return this;
    }

    public void m287a() {
        m288a(null);
    }

    public void m288a(Bundle bundle) {
        if (this.f200b.isEmpty()) {
            throw new IllegalStateException("No intents added to TaskStackBuilder; cannot startActivities");
        }
        Intent[] intentArr = (Intent[]) this.f200b.toArray(new Intent[this.f200b.size()]);
        intentArr[0] = new Intent(intentArr[0]).addFlags(268484608);
        if (!C0020a.m75a(this.f201c, intentArr, bundle)) {
            Intent intent = new Intent(intentArr[intentArr.length - 1]);
            intent.addFlags(268435456);
            this.f201c.startActivity(intent);
        }
    }

    public Iterator iterator() {
        return this.f200b.iterator();
    }
}
