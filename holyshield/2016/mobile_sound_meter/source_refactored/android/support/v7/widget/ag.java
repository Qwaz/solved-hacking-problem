package android.support.v7.widget;

import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.support.v4.p004h.bu;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0240i;
import android.support.v7.p015b.C0241j;
import android.support.v7.p015b.C0243l;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

class ag extends BaseAdapter {
    final /* synthetic */ ActivityChooserView f1278a;
    private C0307z f1279b;
    private int f1280c;
    private boolean f1281d;
    private boolean f1282e;
    private boolean f1283f;

    public int m2462a() {
        int i = 0;
        int i2 = this.f1280c;
        this.f1280c = Integer.MAX_VALUE;
        int makeMeasureSpec = MeasureSpec.makeMeasureSpec(0, 0);
        int makeMeasureSpec2 = MeasureSpec.makeMeasureSpec(0, 0);
        int count = getCount();
        View view = null;
        int i3 = 0;
        while (i < count) {
            view = getView(i, view, null);
            view.measure(makeMeasureSpec, makeMeasureSpec2);
            i3 = Math.max(i3, view.getMeasuredWidth());
            i++;
        }
        this.f1280c = i2;
        return i3;
    }

    public void m2463a(int i) {
        if (this.f1280c != i) {
            this.f1280c = i;
            notifyDataSetChanged();
        }
    }

    public void m2464a(C0307z c0307z) {
        C0307z d = this.f1278a.f1162b.m2469d();
        if (d != null && this.f1278a.isShown()) {
            d.unregisterObserver(this.f1278a.f1169i);
        }
        this.f1279b = c0307z;
        if (c0307z != null && this.f1278a.isShown()) {
            c0307z.registerObserver(this.f1278a.f1169i);
        }
        notifyDataSetChanged();
    }

    public void m2465a(boolean z) {
        if (this.f1283f != z) {
            this.f1283f = z;
            notifyDataSetChanged();
        }
    }

    public void m2466a(boolean z, boolean z2) {
        if (this.f1281d != z || this.f1282e != z2) {
            this.f1281d = z;
            this.f1282e = z2;
            notifyDataSetChanged();
        }
    }

    public ResolveInfo m2467b() {
        return this.f1279b.m2862b();
    }

    public int m2468c() {
        return this.f1279b.m2858a();
    }

    public C0307z m2469d() {
        return this.f1279b;
    }

    public boolean m2470e() {
        return this.f1281d;
    }

    public int getCount() {
        int a = this.f1279b.m2858a();
        if (!(this.f1281d || this.f1279b.m2862b() == null)) {
            a--;
        }
        a = Math.min(a, this.f1280c);
        return this.f1283f ? a + 1 : a;
    }

    public Object getItem(int i) {
        switch (getItemViewType(i)) {
            case C0243l.View_android_theme /*0*/:
                if (!(this.f1281d || this.f1279b.m2862b() == null)) {
                    i++;
                }
                return this.f1279b.m2860a(i);
            case C0243l.View_android_focusable /*1*/:
                return null;
            default:
                throw new IllegalArgumentException();
        }
    }

    public long getItemId(int i) {
        return (long) i;
    }

    public int getItemViewType(int i) {
        return (this.f1283f && i == getCount() - 1) ? 1 : 0;
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        switch (getItemViewType(i)) {
            case C0243l.View_android_theme /*0*/:
                if (view == null || view.getId() != C0238g.list_item) {
                    view = LayoutInflater.from(this.f1278a.getContext()).inflate(C0240i.abc_activity_chooser_view_list_item, viewGroup, false);
                }
                PackageManager packageManager = this.f1278a.getContext().getPackageManager();
                ResolveInfo resolveInfo = (ResolveInfo) getItem(i);
                ((ImageView) view.findViewById(C0238g.icon)).setImageDrawable(resolveInfo.loadIcon(packageManager));
                ((TextView) view.findViewById(C0238g.title)).setText(resolveInfo.loadLabel(packageManager));
                if (this.f1281d && i == 0 && this.f1282e) {
                    bu.m992b(view, true);
                    return view;
                }
                bu.m992b(view, false);
                return view;
            case C0243l.View_android_focusable /*1*/:
                if (view != null && view.getId() == 1) {
                    return view;
                }
                view = LayoutInflater.from(this.f1278a.getContext()).inflate(C0240i.abc_activity_chooser_view_list_item, viewGroup, false);
                view.setId(1);
                ((TextView) view.findViewById(C0238g.title)).setText(this.f1278a.getContext().getString(C0241j.abc_activity_chooser_view_see_all));
                return view;
            default:
                throw new IllegalArgumentException();
        }
    }

    public int getViewTypeCount() {
        return 3;
    }
}
