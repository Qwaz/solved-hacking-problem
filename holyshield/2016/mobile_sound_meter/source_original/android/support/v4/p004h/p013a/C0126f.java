package android.support.v4.p004h.p013a;

import android.graphics.Rect;
import android.os.Build.VERSION;
import android.support.v7.p015b.C0243l;

/* renamed from: android.support.v4.h.a.f */
public class C0126f {
    private static final C0127j f417a;
    private final Object f418b;

    static {
        if (VERSION.SDK_INT >= 22) {
            f417a = new C0135h();
        } else if (VERSION.SDK_INT >= 21) {
            f417a = new C0134g();
        } else if (VERSION.SDK_INT >= 19) {
            f417a = new C0133n();
        } else if (VERSION.SDK_INT >= 18) {
            f417a = new C0132m();
        } else if (VERSION.SDK_INT >= 17) {
            f417a = new C0131l();
        } else if (VERSION.SDK_INT >= 16) {
            f417a = new C0130k();
        } else if (VERSION.SDK_INT >= 14) {
            f417a = new C0129i();
        } else {
            f417a = new C0128o();
        }
    }

    public C0126f(Object obj) {
        this.f418b = obj;
    }

    private static String m701b(int i) {
        switch (i) {
            case C0243l.View_android_focusable /*1*/:
                return "ACTION_FOCUS";
            case C0243l.View_paddingStart /*2*/:
                return "ACTION_CLEAR_FOCUS";
            case C0243l.View_theme /*4*/:
                return "ACTION_SELECT";
            case C0243l.Toolbar_contentInsetRight /*8*/:
                return "ACTION_CLEAR_SELECTION";
            case C0243l.Toolbar_titleMarginBottom /*16*/:
                return "ACTION_CLICK";
            case C0243l.AppCompatTheme_actionModeCutDrawable /*32*/:
                return "ACTION_LONG_CLICK";
            case C0243l.AppCompatTheme_imageButtonStyle /*64*/:
                return "ACTION_ACCESSIBILITY_FOCUS";
            case 128:
                return "ACTION_CLEAR_ACCESSIBILITY_FOCUS";
            case 256:
                return "ACTION_NEXT_AT_MOVEMENT_GRANULARITY";
            case 512:
                return "ACTION_PREVIOUS_AT_MOVEMENT_GRANULARITY";
            case 1024:
                return "ACTION_NEXT_HTML_ELEMENT";
            case 2048:
                return "ACTION_PREVIOUS_HTML_ELEMENT";
            case 4096:
                return "ACTION_SCROLL_FORWARD";
            case 8192:
                return "ACTION_SCROLL_BACKWARD";
            case 16384:
                return "ACTION_COPY";
            case 32768:
                return "ACTION_PASTE";
            case 65536:
                return "ACTION_CUT";
            case 131072:
                return "ACTION_SET_SELECTION";
            default:
                return "ACTION_UNKNOWN";
        }
    }

    public Object m702a() {
        return this.f418b;
    }

    public void m703a(int i) {
        f417a.m725a(this.f418b, i);
    }

    public void m704a(Rect rect) {
        f417a.m726a(this.f418b, rect);
    }

    public void m705a(CharSequence charSequence) {
        f417a.m727a(this.f418b, charSequence);
    }

    public void m706a(boolean z) {
        f417a.m728a(this.f418b, z);
    }

    public int m707b() {
        return f417a.m724a(this.f418b);
    }

    public void m708b(Rect rect) {
        f417a.m730b(this.f418b, rect);
    }

    public boolean m709c() {
        return f417a.m734f(this.f418b);
    }

    public boolean m710d() {
        return f417a.m735g(this.f418b);
    }

    public boolean m711e() {
        return f417a.m738j(this.f418b);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        C0126f c0126f = (C0126f) obj;
        return this.f418b == null ? c0126f.f418b == null : this.f418b.equals(c0126f.f418b);
    }

    public boolean m712f() {
        return f417a.m739k(this.f418b);
    }

    public boolean m713g() {
        return f417a.m743o(this.f418b);
    }

    public boolean m714h() {
        return f417a.m736h(this.f418b);
    }

    public int hashCode() {
        return this.f418b == null ? 0 : this.f418b.hashCode();
    }

    public boolean m715i() {
        return f417a.m740l(this.f418b);
    }

    public boolean m716j() {
        return f417a.m737i(this.f418b);
    }

    public boolean m717k() {
        return f417a.m741m(this.f418b);
    }

    public boolean m718l() {
        return f417a.m742n(this.f418b);
    }

    public CharSequence m719m() {
        return f417a.m732d(this.f418b);
    }

    public CharSequence m720n() {
        return f417a.m729b(this.f418b);
    }

    public CharSequence m721o() {
        return f417a.m733e(this.f418b);
    }

    public CharSequence m722p() {
        return f417a.m731c(this.f418b);
    }

    public String m723q() {
        return f417a.m744p(this.f418b);
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(super.toString());
        Rect rect = new Rect();
        m704a(rect);
        stringBuilder.append("; boundsInParent: " + rect);
        m708b(rect);
        stringBuilder.append("; boundsInScreen: " + rect);
        stringBuilder.append("; packageName: ").append(m719m());
        stringBuilder.append("; className: ").append(m720n());
        stringBuilder.append("; text: ").append(m721o());
        stringBuilder.append("; contentDescription: ").append(m722p());
        stringBuilder.append("; viewId: ").append(m723q());
        stringBuilder.append("; checkable: ").append(m709c());
        stringBuilder.append("; checked: ").append(m710d());
        stringBuilder.append("; focusable: ").append(m711e());
        stringBuilder.append("; focused: ").append(m712f());
        stringBuilder.append("; selected: ").append(m713g());
        stringBuilder.append("; clickable: ").append(m714h());
        stringBuilder.append("; longClickable: ").append(m715i());
        stringBuilder.append("; enabled: ").append(m716j());
        stringBuilder.append("; password: ").append(m717k());
        stringBuilder.append("; scrollable: " + m718l());
        stringBuilder.append("; [");
        int b = m707b();
        while (b != 0) {
            int numberOfTrailingZeros = 1 << Integer.numberOfTrailingZeros(b);
            b &= numberOfTrailingZeros ^ -1;
            stringBuilder.append(C0126f.m701b(numberOfTrailingZeros));
            if (b != 0) {
                stringBuilder.append(", ");
            }
        }
        stringBuilder.append("]");
        return stringBuilder.toString();
    }
}
