package android.support.v4.app;

import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.view.View.BaseSavedState;
import android.widget.TabHost;
import android.widget.TabHost.OnTabChangeListener;
import java.util.ArrayList;

public class FragmentTabHost extends TabHost implements OnTabChangeListener {
    private final ArrayList f74a;
    private Context f75b;
    private C0014l f76c;
    private int f77d;
    private OnTabChangeListener f78e;
    private C0023u f79f;
    private boolean f80g;

    class SavedState extends BaseSavedState {
        public static final Creator CREATOR;
        String f73a;

        static {
            CREATOR = new C0022t();
        }

        private SavedState(Parcel parcel) {
            super(parcel);
            this.f73a = parcel.readString();
        }

        SavedState(Parcelable parcelable) {
            super(parcelable);
        }

        public String toString() {
            return "FragmentTabHost.SavedState{" + Integer.toHexString(System.identityHashCode(this)) + " curTab=" + this.f73a + "}";
        }

        public void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeString(this.f73a);
        }
    }

    private C0003v m66a(String str, C0003v c0003v) {
        C0023u c0023u = null;
        int i = 0;
        while (i < this.f74a.size()) {
            C0023u c0023u2 = (C0023u) this.f74a.get(i);
            if (!c0023u2.f161a.equals(str)) {
                c0023u2 = c0023u;
            }
            i++;
            c0023u = c0023u2;
        }
        if (c0023u == null) {
            throw new IllegalStateException("No tab known for tag " + str);
        }
        if (this.f79f != c0023u) {
            if (c0003v == null) {
                c0003v = this.f76c.m102a();
            }
            if (!(this.f79f == null || this.f79f.f164d == null)) {
                c0003v.m71a(this.f79f.f164d);
            }
            if (c0023u != null) {
                if (c0023u.f164d == null) {
                    c0023u.f164d = Fragment.m12a(this.f75b, c0023u.f162b.getName(), c0023u.f163c);
                    c0003v.m70a(this.f77d, c0023u.f164d, c0023u.f161a);
                } else {
                    c0003v.m72b(c0023u.f164d);
                }
            }
            this.f79f = c0023u;
        }
        return c0003v;
    }

    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        String currentTabTag = getCurrentTabTag();
        C0003v c0003v = null;
        for (int i = 0; i < this.f74a.size(); i++) {
            C0023u c0023u = (C0023u) this.f74a.get(i);
            c0023u.f164d = this.f76c.m101a(c0023u.f161a);
            if (!(c0023u.f164d == null || c0023u.f164d.m40d())) {
                if (c0023u.f161a.equals(currentTabTag)) {
                    this.f79f = c0023u;
                } else {
                    if (c0003v == null) {
                        c0003v = this.f76c.m102a();
                    }
                    c0003v.m71a(c0023u.f164d);
                }
            }
        }
        this.f80g = true;
        C0003v a = m66a(currentTabTag, c0003v);
        if (a != null) {
            a.m69a();
            this.f76c.m103b();
        }
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f80g = false;
    }

    protected void onRestoreInstanceState(Parcelable parcelable) {
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        setCurrentTabByTag(savedState.f73a);
    }

    protected Parcelable onSaveInstanceState() {
        Parcelable savedState = new SavedState(super.onSaveInstanceState());
        savedState.f73a = getCurrentTabTag();
        return savedState;
    }

    public void onTabChanged(String str) {
        if (this.f80g) {
            C0003v a = m66a(str, null);
            if (a != null) {
                a.m69a();
            }
        }
        if (this.f78e != null) {
            this.f78e.onTabChanged(str);
        }
    }

    public void setOnTabChangedListener(OnTabChangeListener onTabChangeListener) {
        this.f78e = onTabChangeListener;
    }

    @Deprecated
    public void setup() {
        throw new IllegalStateException("Must call setup() that takes a Context and FragmentManager");
    }
}
