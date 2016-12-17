package android.support.p000a.p001a;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.animation.AnimatorSet;
import android.animation.ArgbEvaluator;
import android.animation.ObjectAnimator;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.AnimatedVectorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.Callback;
import android.graphics.drawable.Drawable.ConstantState;
import android.os.Build.VERSION;
import android.support.v4.p006c.p007a.C0062a;
import android.support.v4.p012g.C0107a;
import android.util.AttributeSet;
import java.util.ArrayList;
import java.util.List;
import org.xmlpull.v1.XmlPullParser;

@TargetApi(21)
/* renamed from: android.support.a.a.b */
public class C0002b extends C0001k implements Animatable {
    private C0004d f7b;
    private Context f8c;
    private ArgbEvaluator f9d;
    private final Callback f10e;

    private C0002b() {
        this(null, null, null);
    }

    private C0002b(Context context) {
        this(context, null, null);
    }

    private C0002b(Context context, C0004d c0004d, Resources resources) {
        this.f9d = null;
        this.f10e = new C0003c(this);
        this.f8c = context;
        if (c0004d != null) {
            this.f7b = c0004d;
        } else {
            this.f7b = new C0004d(context, c0004d, this.f10e, resources);
        }
    }

    static TypedArray m1a(Resources resources, Theme theme, AttributeSet attributeSet, int[] iArr) {
        return theme == null ? resources.obtainAttributes(attributeSet, iArr) : theme.obtainStyledAttributes(attributeSet, iArr, 0, 0);
    }

    public static C0002b m3a(Context context, Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        C0002b c0002b = new C0002b(context);
        c0002b.inflate(resources, xmlPullParser, attributeSet, theme);
        return c0002b;
    }

    private void m4a(Animator animator) {
        if (animator instanceof AnimatorSet) {
            List childAnimations = ((AnimatorSet) animator).getChildAnimations();
            if (childAnimations != null) {
                for (int i = 0; i < childAnimations.size(); i++) {
                    m4a((Animator) childAnimations.get(i));
                }
            }
        }
        if (animator instanceof ObjectAnimator) {
            ObjectAnimator objectAnimator = (ObjectAnimator) animator;
            String propertyName = objectAnimator.getPropertyName();
            if ("fillColor".equals(propertyName) || "strokeColor".equals(propertyName)) {
                if (this.f9d == null) {
                    this.f9d = new ArgbEvaluator();
                }
                objectAnimator.setEvaluator(this.f9d);
            }
        }
    }

    private void m5a(String str, Animator animator) {
        animator.setTarget(this.f7b.f13b.m33a(str));
        if (VERSION.SDK_INT < 21) {
            m4a(animator);
        }
        if (this.f7b.f14c == null) {
            this.f7b.f14c = new ArrayList();
            this.f7b.f15d = new C0107a();
        }
        this.f7b.f14c.add(animator);
        this.f7b.f15d.put(animator, str);
    }

    private boolean m6a() {
        ArrayList arrayList = this.f7b.f14c;
        if (arrayList == null) {
            return false;
        }
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            if (((Animator) arrayList.get(i)).isRunning()) {
                return true;
            }
        }
        return false;
    }

    public void applyTheme(Theme theme) {
        if (this.a != null) {
            C0062a.m459a(this.a, theme);
        }
    }

    public boolean canApplyTheme() {
        return this.a != null ? C0062a.m465d(this.a) : false;
    }

    public /* bridge */ /* synthetic */ void clearColorFilter() {
        super.clearColorFilter();
    }

    public void draw(Canvas canvas) {
        if (this.a != null) {
            this.a.draw(canvas);
            return;
        }
        this.f7b.f13b.draw(canvas);
        if (m6a()) {
            invalidateSelf();
        }
    }

    public int getAlpha() {
        return this.a != null ? C0062a.m464c(this.a) : this.f7b.f13b.getAlpha();
    }

    public int getChangingConfigurations() {
        return this.a != null ? this.a.getChangingConfigurations() : super.getChangingConfigurations() | this.f7b.f12a;
    }

    public /* bridge */ /* synthetic */ ColorFilter getColorFilter() {
        return super.getColorFilter();
    }

    public ConstantState getConstantState() {
        return this.a != null ? new C0005e(this.a.getConstantState()) : null;
    }

    public /* bridge */ /* synthetic */ Drawable getCurrent() {
        return super.getCurrent();
    }

    public int getIntrinsicHeight() {
        return this.a != null ? this.a.getIntrinsicHeight() : this.f7b.f13b.getIntrinsicHeight();
    }

    public int getIntrinsicWidth() {
        return this.a != null ? this.a.getIntrinsicWidth() : this.f7b.f13b.getIntrinsicWidth();
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
        return this.a != null ? this.a.getOpacity() : this.f7b.f13b.getOpacity();
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
        inflate(resources, xmlPullParser, attributeSet, null);
    }

    public void inflate(Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        if (this.a != null) {
            C0062a.m460a(this.a, resources, xmlPullParser, attributeSet, theme);
            return;
        }
        int eventType = xmlPullParser.getEventType();
        while (eventType != 1) {
            if (eventType == 2) {
                String name = xmlPullParser.getName();
                TypedArray a;
                if ("animated-vector".equals(name)) {
                    a = C0002b.m1a(resources, theme, attributeSet, C0000a.f4e);
                    int resourceId = a.getResourceId(0, 0);
                    if (resourceId != 0) {
                        C0011l a2 = C0011l.m26a(resources, resourceId, theme);
                        a2.m34a(false);
                        a2.setCallback(this.f10e);
                        if (this.f7b.f13b != null) {
                            this.f7b.f13b.setCallback(null);
                        }
                        this.f7b.f13b = a2;
                    }
                    a.recycle();
                } else if ("target".equals(name)) {
                    a = resources.obtainAttributes(attributeSet, C0000a.f5f);
                    String string = a.getString(0);
                    int resourceId2 = a.getResourceId(1, 0);
                    if (resourceId2 != 0) {
                        if (this.f8c != null) {
                            m5a(string, AnimatorInflater.loadAnimator(this.f8c, resourceId2));
                        } else {
                            throw new IllegalStateException("Context can't be null when inflating animators");
                        }
                    }
                    a.recycle();
                } else {
                    continue;
                }
            }
            eventType = xmlPullParser.next();
        }
    }

    public /* bridge */ /* synthetic */ boolean isAutoMirrored() {
        return super.isAutoMirrored();
    }

    public boolean isRunning() {
        if (this.a != null) {
            return ((AnimatedVectorDrawable) this.a).isRunning();
        }
        ArrayList arrayList = this.f7b.f14c;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            if (((Animator) arrayList.get(i)).isRunning()) {
                return true;
            }
        }
        return false;
    }

    public boolean isStateful() {
        return this.a != null ? this.a.isStateful() : this.f7b.f13b.isStateful();
    }

    public /* bridge */ /* synthetic */ void jumpToCurrentState() {
        super.jumpToCurrentState();
    }

    public Drawable mutate() {
        if (this.a != null) {
            this.a.mutate();
            return this;
        }
        throw new IllegalStateException("Mutate() is not supported for older platform");
    }

    protected void onBoundsChange(Rect rect) {
        if (this.a != null) {
            this.a.setBounds(rect);
        } else {
            this.f7b.f13b.setBounds(rect);
        }
    }

    protected boolean onLevelChange(int i) {
        return this.a != null ? this.a.setLevel(i) : this.f7b.f13b.setLevel(i);
    }

    protected boolean onStateChange(int[] iArr) {
        return this.a != null ? this.a.setState(iArr) : this.f7b.f13b.setState(iArr);
    }

    public void setAlpha(int i) {
        if (this.a != null) {
            this.a.setAlpha(i);
        } else {
            this.f7b.f13b.setAlpha(i);
        }
    }

    public /* bridge */ /* synthetic */ void setAutoMirrored(boolean z) {
        super.setAutoMirrored(z);
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
        } else {
            this.f7b.f13b.setColorFilter(colorFilter);
        }
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
            this.f7b.f13b.setTint(i);
        }
    }

    public void setTintList(ColorStateList colorStateList) {
        if (this.a != null) {
            C0062a.m458a(this.a, colorStateList);
        } else {
            this.f7b.f13b.setTintList(colorStateList);
        }
    }

    public void setTintMode(Mode mode) {
        if (this.a != null) {
            C0062a.m461a(this.a, mode);
        } else {
            this.f7b.f13b.setTintMode(mode);
        }
    }

    public boolean setVisible(boolean z, boolean z2) {
        if (this.a != null) {
            return this.a.setVisible(z, z2);
        }
        this.f7b.f13b.setVisible(z, z2);
        return super.setVisible(z, z2);
    }

    public void start() {
        if (this.a != null) {
            ((AnimatedVectorDrawable) this.a).start();
        } else if (!m6a()) {
            ArrayList arrayList = this.f7b.f14c;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                ((Animator) arrayList.get(i)).start();
            }
            invalidateSelf();
        }
    }

    public void stop() {
        if (this.a != null) {
            ((AnimatedVectorDrawable) this.a).stop();
            return;
        }
        ArrayList arrayList = this.f7b.f14c;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((Animator) arrayList.get(i)).end();
        }
    }
}
