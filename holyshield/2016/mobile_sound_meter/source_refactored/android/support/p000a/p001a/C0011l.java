package android.support.p000a.p001a;

import android.annotation.TargetApi;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.os.Build.VERSION;
import android.support.v4.p002b.p005a.C0049a;
import android.support.v4.p006c.p007a.C0062a;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.util.Log;
import android.util.Xml;
import java.util.Stack;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

@TargetApi(21)
/* renamed from: android.support.a.a.l */
public class C0011l extends C0001k {
    static final Mode f21b;
    private C0018s f22c;
    private PorterDuffColorFilter f23d;
    private ColorFilter f24e;
    private boolean f25f;
    private boolean f26g;
    private ConstantState f27h;
    private final float[] f28i;
    private final Matrix f29j;
    private final Rect f30k;

    static {
        f21b = Mode.SRC_IN;
    }

    private C0011l() {
        this.f26g = true;
        this.f28i = new float[9];
        this.f29j = new Matrix();
        this.f30k = new Rect();
        this.f22c = new C0018s();
    }

    private C0011l(C0018s c0018s) {
        this.f26g = true;
        this.f28i = new float[9];
        this.f29j = new Matrix();
        this.f30k = new Rect();
        this.f22c = c0018s;
        this.f23d = m32a(this.f23d, c0018s.f78c, c0018s.f79d);
    }

    private static Mode m25a(int i, Mode mode) {
        switch (i) {
            case C0243l.View_paddingEnd /*3*/:
                return Mode.SRC_OVER;
            case C0243l.Toolbar_contentInsetStart /*5*/:
                return Mode.SRC_IN;
            case C0243l.Toolbar_popupTheme /*9*/:
                return Mode.SRC_ATOP;
            case C0243l.Toolbar_titleMarginEnd /*14*/:
                return Mode.MULTIPLY;
            case C0243l.Toolbar_titleMarginTop /*15*/:
                return Mode.SCREEN;
            case C0243l.Toolbar_titleMarginBottom /*16*/:
                return Mode.ADD;
            default:
                return mode;
        }
    }

    public static C0011l m26a(Resources resources, int i, Theme theme) {
        if (VERSION.SDK_INT >= 23) {
            C0011l c0011l = new C0011l();
            c0011l.a = C0049a.m430a(resources, i, theme);
            c0011l.f27h = new C0019t(c0011l.a.getConstantState());
            return c0011l;
        }
        try {
            int next;
            XmlPullParser xml = resources.getXml(i);
            AttributeSet asAttributeSet = Xml.asAttributeSet(xml);
            do {
                next = xml.next();
                if (next == 2) {
                    break;
                }
            } while (next != 1);
            if (next == 2) {
                return C0011l.m27a(resources, xml, asAttributeSet, theme);
            }
            throw new XmlPullParserException("No start tag found");
        } catch (Throwable e) {
            Log.e("VectorDrawableCompat", "parser error", e);
            return null;
        } catch (Throwable e2) {
            Log.e("VectorDrawableCompat", "parser error", e2);
            return null;
        }
    }

    public static C0011l m27a(Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        C0011l c0011l = new C0011l();
        c0011l.inflate(resources, xmlPullParser, attributeSet, theme);
        return c0011l;
    }

    private void m28a(TypedArray typedArray, XmlPullParser xmlPullParser) {
        C0018s c0018s = this.f22c;
        C0017r c0017r = c0018s.f77b;
        c0018s.f79d = C0011l.m25a(C0010j.m20a(typedArray, xmlPullParser, "tintMode", 6, -1), Mode.SRC_IN);
        ColorStateList colorStateList = typedArray.getColorStateList(1);
        if (colorStateList != null) {
            c0018s.f78c = colorStateList;
        }
        c0018s.f80e = C0010j.m21a(typedArray, xmlPullParser, "autoMirrored", 5, c0018s.f80e);
        c0017r.f63c = C0010j.m19a(typedArray, xmlPullParser, "viewportWidth", 7, c0017r.f63c);
        c0017r.f64d = C0010j.m19a(typedArray, xmlPullParser, "viewportHeight", 8, c0017r.f64d);
        if (c0017r.f63c <= 0.0f) {
            throw new XmlPullParserException(typedArray.getPositionDescription() + "<vector> tag requires viewportWidth > 0");
        } else if (c0017r.f64d <= 0.0f) {
            throw new XmlPullParserException(typedArray.getPositionDescription() + "<vector> tag requires viewportHeight > 0");
        } else {
            c0017r.f61a = typedArray.getDimension(3, c0017r.f61a);
            c0017r.f62b = typedArray.getDimension(2, c0017r.f62b);
            if (c0017r.f61a <= 0.0f) {
                throw new XmlPullParserException(typedArray.getPositionDescription() + "<vector> tag requires width > 0");
            } else if (c0017r.f62b <= 0.0f) {
                throw new XmlPullParserException(typedArray.getPositionDescription() + "<vector> tag requires height > 0");
            } else {
                c0017r.m62a(C0010j.m19a(typedArray, xmlPullParser, "alpha", 4, c0017r.m65b()));
                String string = typedArray.getString(0);
                if (string != null) {
                    c0017r.f66f = string;
                    c0017r.f67g.put(string, c0017r);
                }
            }
        }
    }

    private boolean m29a() {
        return false;
    }

    private static int m30b(int i, float f) {
        return (((int) (((float) Color.alpha(i)) * f)) << 24) | (16777215 & i);
    }

    private void m31b(Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        C0018s c0018s = this.f22c;
        C0017r c0017r = c0018s.f77b;
        Stack stack = new Stack();
        stack.push(c0017r.f75p);
        int eventType = xmlPullParser.getEventType();
        Object obj = 1;
        while (eventType != 1) {
            if (eventType == 2) {
                Object obj2;
                String name = xmlPullParser.getName();
                C0016p c0016p = (C0016p) stack.peek();
                if ("path".equals(name)) {
                    C0015o c0015o = new C0015o();
                    c0015o.m44a(resources, attributeSet, theme, xmlPullParser);
                    c0016p.f47a.add(c0015o);
                    if (c0015o.m37b() != null) {
                        c0017r.f67g.put(c0015o.m37b(), c0015o);
                    }
                    obj2 = null;
                    c0018s.f76a = c0015o.o | c0018s.f76a;
                } else if ("clip-path".equals(name)) {
                    C0014n c0014n = new C0014n();
                    c0014n.m39a(resources, attributeSet, theme, xmlPullParser);
                    c0016p.f47a.add(c0014n);
                    if (c0014n.m37b() != null) {
                        c0017r.f67g.put(c0014n.m37b(), c0014n);
                    }
                    c0018s.f76a |= c0014n.o;
                    obj2 = obj;
                } else {
                    if ("group".equals(name)) {
                        C0016p c0016p2 = new C0016p();
                        c0016p2.m51a(resources, attributeSet, theme, xmlPullParser);
                        c0016p.f47a.add(c0016p2);
                        stack.push(c0016p2);
                        if (c0016p2.m50a() != null) {
                            c0017r.f67g.put(c0016p2.m50a(), c0016p2);
                        }
                        c0018s.f76a |= c0016p2.f57k;
                    }
                    obj2 = obj;
                }
                obj = obj2;
            } else if (eventType == 3) {
                if ("group".equals(xmlPullParser.getName())) {
                    stack.pop();
                }
            }
            eventType = xmlPullParser.next();
        }
        if (obj != null) {
            StringBuffer stringBuffer = new StringBuffer();
            if (stringBuffer.length() > 0) {
                stringBuffer.append(" or ");
            }
            stringBuffer.append("path");
            throw new XmlPullParserException("no " + stringBuffer + " defined");
        }
    }

    PorterDuffColorFilter m32a(PorterDuffColorFilter porterDuffColorFilter, ColorStateList colorStateList, Mode mode) {
        return (colorStateList == null || mode == null) ? null : new PorterDuffColorFilter(colorStateList.getColorForState(getState(), 0), mode);
    }

    Object m33a(String str) {
        return this.f22c.f77b.f67g.get(str);
    }

    void m34a(boolean z) {
        this.f26g = z;
    }

    public /* bridge */ /* synthetic */ void applyTheme(Theme theme) {
        super.applyTheme(theme);
    }

    public boolean canApplyTheme() {
        if (this.a != null) {
            C0062a.m465d(this.a);
        }
        return false;
    }

    public /* bridge */ /* synthetic */ void clearColorFilter() {
        super.clearColorFilter();
    }

    public void draw(Canvas canvas) {
        if (this.a != null) {
            this.a.draw(canvas);
            return;
        }
        copyBounds(this.f30k);
        if (this.f30k.width() > 0 && this.f30k.height() > 0) {
            ColorFilter colorFilter = this.f24e == null ? this.f23d : this.f24e;
            canvas.getMatrix(this.f29j);
            this.f29j.getValues(this.f28i);
            float abs = Math.abs(this.f28i[0]);
            float abs2 = Math.abs(this.f28i[4]);
            float abs3 = Math.abs(this.f28i[1]);
            float abs4 = Math.abs(this.f28i[3]);
            if (!(abs3 == 0.0f && abs4 == 0.0f)) {
                abs2 = 1.0f;
                abs = 1.0f;
            }
            int height = (int) (abs2 * ((float) this.f30k.height()));
            int min = Math.min(2048, (int) (abs * ((float) this.f30k.width())));
            height = Math.min(2048, height);
            if (min > 0 && height > 0) {
                int save = canvas.save();
                canvas.translate((float) this.f30k.left, (float) this.f30k.top);
                if (m29a()) {
                    canvas.translate((float) this.f30k.width(), 0.0f);
                    canvas.scale(-1.0f, 1.0f);
                }
                this.f30k.offsetTo(0, 0);
                this.f22c.m70b(min, height);
                if (!this.f26g) {
                    this.f22c.m67a(min, height);
                } else if (!this.f22c.m71b()) {
                    this.f22c.m67a(min, height);
                    this.f22c.m72c();
                }
                this.f22c.m68a(canvas, colorFilter, this.f30k);
                canvas.restoreToCount(save);
            }
        }
    }

    public int getAlpha() {
        return this.a != null ? C0062a.m464c(this.a) : this.f22c.f77b.m61a();
    }

    public int getChangingConfigurations() {
        return this.a != null ? this.a.getChangingConfigurations() : super.getChangingConfigurations() | this.f22c.getChangingConfigurations();
    }

    public /* bridge */ /* synthetic */ ColorFilter getColorFilter() {
        return super.getColorFilter();
    }

    public ConstantState getConstantState() {
        if (this.a != null) {
            return new C0019t(this.a.getConstantState());
        }
        this.f22c.f76a = getChangingConfigurations();
        return this.f22c;
    }

    public /* bridge */ /* synthetic */ Drawable getCurrent() {
        return super.getCurrent();
    }

    public int getIntrinsicHeight() {
        return this.a != null ? this.a.getIntrinsicHeight() : (int) this.f22c.f77b.f62b;
    }

    public int getIntrinsicWidth() {
        return this.a != null ? this.a.getIntrinsicWidth() : (int) this.f22c.f77b.f61a;
    }

    public /* bridge */ /* synthetic */ int getLayoutDirection() {
        return super.getLayoutDirection();
    }

    public /* bridge */ /* synthetic */ int getMinimumHeight() {
        return super.getMinimumHeight();
    }

    public /* bridge */ /* synthetic */ int getMinimumWidth() {
        return super.getMinimumWidth();
    }

    public int getOpacity() {
        return this.a != null ? this.a.getOpacity() : -3;
    }

    public /* bridge */ /* synthetic */ boolean getPadding(Rect rect) {
        return super.getPadding(rect);
    }

    public /* bridge */ /* synthetic */ int[] getState() {
        return super.getState();
    }

    public /* bridge */ /* synthetic */ Region getTransparentRegion() {
        return super.getTransparentRegion();
    }

    public void inflate(Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet) {
        if (this.a != null) {
            this.a.inflate(resources, xmlPullParser, attributeSet);
        } else {
            inflate(resources, xmlPullParser, attributeSet, null);
        }
    }

    public void inflate(Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        if (this.a != null) {
            C0062a.m460a(this.a, resources, xmlPullParser, attributeSet, theme);
            return;
        }
        C0018s c0018s = this.f22c;
        c0018s.f77b = new C0017r();
        TypedArray b = C0001k.m0b(resources, theme, attributeSet, C0000a.f0a);
        m28a(b, xmlPullParser);
        b.recycle();
        c0018s.f76a = getChangingConfigurations();
        c0018s.f86k = true;
        m31b(resources, xmlPullParser, attributeSet, theme);
        this.f23d = m32a(this.f23d, c0018s.f78c, c0018s.f79d);
    }

    public void invalidateSelf() {
        if (this.a != null) {
            this.a.invalidateSelf();
        } else {
            super.invalidateSelf();
        }
    }

    public /* bridge */ /* synthetic */ boolean isAutoMirrored() {
        return super.isAutoMirrored();
    }

    public boolean isStateful() {
        return this.a != null ? this.a.isStateful() : super.isStateful() || !(this.f22c == null || this.f22c.f78c == null || !this.f22c.f78c.isStateful());
    }

    public /* bridge */ /* synthetic */ void jumpToCurrentState() {
        super.jumpToCurrentState();
    }

    public Drawable mutate() {
        if (this.a != null) {
            this.a.mutate();
        } else if (!this.f25f && super.mutate() == this) {
            this.f22c = new C0018s(this.f22c);
            this.f25f = true;
        }
        return this;
    }

    protected boolean onStateChange(int[] iArr) {
        if (this.a != null) {
            return this.a.setState(iArr);
        }
        C0018s c0018s = this.f22c;
        if (c0018s.f78c == null || c0018s.f79d == null) {
            return false;
        }
        this.f23d = m32a(this.f23d, c0018s.f78c, c0018s.f79d);
        invalidateSelf();
        return true;
    }

    public void scheduleSelf(Runnable runnable, long j) {
        if (this.a != null) {
            this.a.scheduleSelf(runnable, j);
        } else {
            super.scheduleSelf(runnable, j);
        }
    }

    public void setAlpha(int i) {
        if (this.a != null) {
            this.a.setAlpha(i);
        } else if (this.f22c.f77b.m61a() != i) {
            this.f22c.f77b.m63a(i);
            invalidateSelf();
        }
    }

    public /* bridge */ /* synthetic */ void setAutoMirrored(boolean z) {
        super.setAutoMirrored(z);
    }

    public void setBounds(int i, int i2, int i3, int i4) {
        if (this.a != null) {
            this.a.setBounds(i, i2, i3, i4);
        } else {
            super.setBounds(i, i2, i3, i4);
        }
    }

    public void setBounds(Rect rect) {
        if (this.a != null) {
            this.a.setBounds(rect);
        } else {
            super.setBounds(rect);
        }
    }

    public /* bridge */ /* synthetic */ void setChangingConfigurations(int i) {
        super.setChangingConfigurations(i);
    }

    public /* bridge */ /* synthetic */ void setColorFilter(int i, Mode mode) {
        super.setColorFilter(i, mode);
    }

    public void setColorFilter(ColorFilter colorFilter) {
        if (this.a != null) {
            this.a.setColorFilter(colorFilter);
            return;
        }
        this.f24e = colorFilter;
        invalidateSelf();
    }

    public /* bridge */ /* synthetic */ void setFilterBitmap(boolean z) {
        super.setFilterBitmap(z);
    }

    public /* bridge */ /* synthetic */ void setHotspot(float f, float f2) {
        super.setHotspot(f, f2);
    }

    public /* bridge */ /* synthetic */ void setHotspotBounds(int i, int i2, int i3, int i4) {
        super.setHotspotBounds(i, i2, i3, i4);
    }

    public /* bridge */ /* synthetic */ boolean setState(int[] iArr) {
        return super.setState(iArr);
    }

    public void setTint(int i) {
        if (this.a != null) {
            C0062a.m456a(this.a, i);
        } else {
            setTintList(ColorStateList.valueOf(i));
        }
    }

    public void setTintList(ColorStateList colorStateList) {
        if (this.a != null) {
            C0062a.m458a(this.a, colorStateList);
            return;
        }
        C0018s c0018s = this.f22c;
        if (c0018s.f78c != colorStateList) {
            c0018s.f78c = colorStateList;
            this.f23d = m32a(this.f23d, colorStateList, c0018s.f79d);
            invalidateSelf();
        }
    }

    public void setTintMode(Mode mode) {
        if (this.a != null) {
            C0062a.m461a(this.a, mode);
            return;
        }
        C0018s c0018s = this.f22c;
        if (c0018s.f79d != mode) {
            c0018s.f79d = mode;
            this.f23d = m32a(this.f23d, c0018s.f78c, mode);
            invalidateSelf();
        }
    }

    public boolean setVisible(boolean z, boolean z2) {
        return this.a != null ? this.a.setVisible(z, z2) : super.setVisible(z, z2);
    }

    public void unscheduleSelf(Runnable runnable) {
        if (this.a != null) {
            this.a.unscheduleSelf(runnable);
        } else {
            super.unscheduleSelf(runnable);
        }
    }
}
