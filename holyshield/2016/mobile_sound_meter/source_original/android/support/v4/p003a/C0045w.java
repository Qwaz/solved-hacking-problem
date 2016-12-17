package android.support.v4.p003a;

import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.os.Parcelable;
import android.support.v4.p012g.C0106n;
import android.support.v4.p012g.C0120o;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.util.Log;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.List;

/* renamed from: android.support.v4.a.w */
public class C0045w extends C0041s {
    final Handler f318a;
    final ab f319b;
    boolean f320c;
    boolean f321d;
    boolean f322e;
    boolean f323f;
    boolean f324g;
    boolean f325h;
    int f326i;
    boolean f327j;
    C0120o f328k;

    public C0045w() {
        this.f318a = new C0046x(this);
        this.f319b = ab.m80a(new C0047y(this));
    }

    private static String m411a(View view) {
        char c = 'F';
        char c2 = '.';
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append(view.getClass().getName());
        stringBuilder.append('{');
        stringBuilder.append(Integer.toHexString(System.identityHashCode(view)));
        stringBuilder.append(' ');
        switch (view.getVisibility()) {
            case C0243l.View_android_theme /*0*/:
                stringBuilder.append('V');
                break;
            case C0243l.View_theme /*4*/:
                stringBuilder.append('I');
                break;
            case C0243l.Toolbar_contentInsetRight /*8*/:
                stringBuilder.append('G');
                break;
            default:
                stringBuilder.append('.');
                break;
        }
        stringBuilder.append(view.isFocusable() ? 'F' : '.');
        stringBuilder.append(view.isEnabled() ? 'E' : '.');
        stringBuilder.append(view.willNotDraw() ? '.' : 'D');
        stringBuilder.append(view.isHorizontalScrollBarEnabled() ? 'H' : '.');
        stringBuilder.append(view.isVerticalScrollBarEnabled() ? 'V' : '.');
        stringBuilder.append(view.isClickable() ? 'C' : '.');
        stringBuilder.append(view.isLongClickable() ? 'L' : '.');
        stringBuilder.append(' ');
        if (!view.isFocused()) {
            c = '.';
        }
        stringBuilder.append(c);
        stringBuilder.append(view.isSelected() ? 'S' : '.');
        if (view.isPressed()) {
            c2 = 'P';
        }
        stringBuilder.append(c2);
        stringBuilder.append(' ');
        stringBuilder.append(view.getLeft());
        stringBuilder.append(',');
        stringBuilder.append(view.getTop());
        stringBuilder.append('-');
        stringBuilder.append(view.getRight());
        stringBuilder.append(',');
        stringBuilder.append(view.getBottom());
        int id = view.getId();
        if (id != -1) {
            stringBuilder.append(" #");
            stringBuilder.append(Integer.toHexString(id));
            Resources resources = view.getResources();
            if (!(id == 0 || resources == null)) {
                String str;
                switch (-16777216 & id) {
                    case 16777216:
                        str = "android";
                        break;
                    case 2130706432:
                        str = "app";
                        break;
                    default:
                        try {
                            str = resources.getResourcePackageName(id);
                            break;
                        } catch (NotFoundException e) {
                            break;
                        }
                }
                String resourceTypeName = resources.getResourceTypeName(id);
                String resourceEntryName = resources.getResourceEntryName(id);
                stringBuilder.append(" ");
                stringBuilder.append(str);
                stringBuilder.append(":");
                stringBuilder.append(resourceTypeName);
                stringBuilder.append("/");
                stringBuilder.append(resourceEntryName);
            }
        }
        stringBuilder.append("}");
        return stringBuilder.toString();
    }

    private void m412a(String str, PrintWriter printWriter, View view) {
        printWriter.print(str);
        if (view == null) {
            printWriter.println("null");
            return;
        }
        printWriter.println(C0045w.m411a(view));
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int childCount = viewGroup.getChildCount();
            if (childCount > 0) {
                String str2 = str + "  ";
                for (int i = 0; i < childCount; i++) {
                    m412a(str2, printWriter, viewGroup.getChildAt(i));
                }
            }
        }
    }

    final View m413a(View view, String str, Context context, AttributeSet attributeSet) {
        return this.f319b.m83a(view, str, context, attributeSet);
    }

    public void m414a(C0042t c0042t) {
    }

    void m415a(boolean z) {
        if (!this.f323f) {
            this.f323f = true;
            this.f324g = z;
            this.f318a.removeMessages(1);
            m420e();
        }
    }

    protected boolean m416a(View view, Menu menu) {
        return super.onPreparePanel(0, view, menu);
    }

    public void a_() {
        C0021a.m77b(this);
    }

    protected void m417b() {
        this.f319b.m101h();
    }

    public Object m418c() {
        return null;
    }

    public void m419d() {
        if (VERSION.SDK_INT >= 11) {
            C0025c.m290a(this);
        } else {
            this.f325h = true;
        }
    }

    public void dump(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        String str2;
        if (VERSION.SDK_INT >= 11) {
            printWriter.print(str);
            printWriter.print("Local FragmentActivity ");
            printWriter.print(Integer.toHexString(System.identityHashCode(this)));
            printWriter.println(" State:");
            str2 = str + "  ";
            printWriter.print(str2);
            printWriter.print("mCreated=");
            printWriter.print(this.f320c);
            printWriter.print("mResumed=");
            printWriter.print(this.f321d);
            printWriter.print(" mStopped=");
            printWriter.print(this.f322e);
            printWriter.print(" mReallyStopped=");
            printWriter.println(this.f323f);
            this.f319b.m88a(str2, fileDescriptor, printWriter, strArr);
            this.f319b.m81a().m135a(str, fileDescriptor, printWriter, strArr);
            printWriter.print(str);
            printWriter.println("View Hierarchy:");
            m412a(str + "  ", printWriter, getWindow().getDecorView());
        } else {
            printWriter.print(str);
            printWriter.print("Local FragmentActivity ");
            printWriter.print(Integer.toHexString(System.identityHashCode(this)));
            printWriter.println(" State:");
            str2 = str + "  ";
            printWriter.print(str2);
            printWriter.print("mCreated=");
            printWriter.print(this.f320c);
            printWriter.print("mResumed=");
            printWriter.print(this.f321d);
            printWriter.print(" mStopped=");
            printWriter.print(this.f322e);
            printWriter.print(" mReallyStopped=");
            printWriter.println(this.f323f);
            this.f319b.m88a(str2, fileDescriptor, printWriter, strArr);
            this.f319b.m81a().m135a(str, fileDescriptor, printWriter, strArr);
            printWriter.print(str);
            printWriter.println("View Hierarchy:");
            m412a(str + "  ", printWriter, getWindow().getDecorView());
        }
    }

    void m420e() {
        this.f319b.m89a(this.f324g);
        this.f319b.m104k();
    }

    protected void onActivityResult(int i, int i2, Intent intent) {
        this.f319b.m93b();
        int i3 = i >> 16;
        if (i3 != 0) {
            int i4 = i3 - 1;
            String str = (String) this.f328k.m658a(i4);
            this.f328k.m664c(i4);
            if (str == null) {
                Log.w("FragmentActivity", "Activity result delivered for unknown Fragment.");
                return;
            }
            C0042t a = this.f319b.m82a(str);
            if (a == null) {
                Log.w("FragmentActivity", "Activity result no fragment exists for who: " + str);
                return;
            } else {
                a.m352a(65535 & i, i2, intent);
                return;
            }
        }
        super.onActivityResult(i, i2, intent);
    }

    public void onBackPressed() {
        if (!this.f319b.m81a().m136a()) {
            a_();
        }
    }

    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        this.f319b.m84a(configuration);
    }

    protected void onCreate(Bundle bundle) {
        this.f319b.m86a(null);
        super.onCreate(bundle);
        C0048z c0048z = (C0048z) getLastNonConfigurationInstance();
        if (c0048z != null) {
            this.f319b.m87a(c0048z.f333c);
        }
        if (bundle != null) {
            this.f319b.m85a(bundle.getParcelable("android:support:fragments"), c0048z != null ? c0048z.f332b : null);
            if (bundle.containsKey("android:support:next_request_index")) {
                this.f326i = bundle.getInt("android:support:next_request_index");
                int[] intArray = bundle.getIntArray("android:support:request_indicies");
                String[] stringArray = bundle.getStringArray("android:support:request_fragment_who");
                if (intArray == null || stringArray == null || intArray.length != stringArray.length) {
                    Log.w("FragmentActivity", "Invalid requestCode mapping in savedInstanceState.");
                } else {
                    this.f328k = new C0120o(intArray.length);
                    for (int i = 0; i < intArray.length; i++) {
                        this.f328k.m662b(intArray[i], stringArray[i]);
                    }
                }
            }
        }
        if (this.f328k == null) {
            this.f328k = new C0120o();
            this.f326i = 0;
        }
        this.f319b.m98e();
    }

    public boolean onCreatePanelMenu(int i, Menu menu) {
        if (i != 0) {
            return super.onCreatePanelMenu(i, menu);
        }
        return VERSION.SDK_INT >= 11 ? super.onCreatePanelMenu(i, menu) | this.f319b.m91a(menu, getMenuInflater()) : true;
    }

    public /* bridge */ /* synthetic */ View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        return super.onCreateView(view, str, context, attributeSet);
    }

    public /* bridge */ /* synthetic */ View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return super.onCreateView(str, context, attributeSet);
    }

    protected void onDestroy() {
        super.onDestroy();
        m415a(false);
        this.f319b.m105l();
        this.f319b.m109p();
    }

    public boolean onKeyDown(int i, KeyEvent keyEvent) {
        if (VERSION.SDK_INT >= 5 || i != 4 || keyEvent.getRepeatCount() != 0) {
            return super.onKeyDown(i, keyEvent);
        }
        onBackPressed();
        return true;
    }

    public void onLowMemory() {
        super.onLowMemory();
        this.f319b.m106m();
    }

    public boolean onMenuItemSelected(int i, MenuItem menuItem) {
        if (super.onMenuItemSelected(i, menuItem)) {
            return true;
        }
        switch (i) {
            case C0243l.View_android_theme /*0*/:
                return this.f319b.m92a(menuItem);
            case C0243l.Toolbar_contentInsetEnd /*6*/:
                return this.f319b.m95b(menuItem);
            default:
                return false;
        }
    }

    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        this.f319b.m93b();
    }

    public void onPanelClosed(int i, Menu menu) {
        switch (i) {
            case C0243l.View_android_theme /*0*/:
                this.f319b.m94b(menu);
                break;
        }
        super.onPanelClosed(i, menu);
    }

    protected void onPause() {
        super.onPause();
        this.f321d = false;
        if (this.f318a.hasMessages(2)) {
            this.f318a.removeMessages(2);
            m417b();
        }
        this.f319b.m102i();
    }

    protected void onPostResume() {
        super.onPostResume();
        this.f318a.removeMessages(2);
        m417b();
        this.f319b.m107n();
    }

    public boolean onPreparePanel(int i, View view, Menu menu) {
        if (i != 0 || menu == null) {
            return super.onPreparePanel(i, view, menu);
        }
        if (this.f325h) {
            this.f325h = false;
            menu.clear();
            onCreatePanelMenu(i, menu);
        }
        return m416a(view, menu) | this.f319b.m90a(menu);
    }

    public void onRequestPermissionsResult(int i, String[] strArr, int[] iArr) {
        int i2 = (i >> 16) & 65535;
        if (i2 != 0) {
            int i3 = i2 - 1;
            String str = (String) this.f328k.m658a(i3);
            this.f328k.m664c(i3);
            if (str == null) {
                Log.w("FragmentActivity", "Activity result delivered for unknown Fragment.");
                return;
            }
            C0042t a = this.f319b.m82a(str);
            if (a == null) {
                Log.w("FragmentActivity", "Activity result no fragment exists for who: " + str);
            } else {
                a.m354a(i & 65535, strArr, iArr);
            }
        }
    }

    protected void onResume() {
        super.onResume();
        this.f318a.sendEmptyMessage(2);
        this.f321d = true;
        this.f319b.m107n();
    }

    public final Object onRetainNonConfigurationInstance() {
        if (this.f322e) {
            m415a(true);
        }
        Object c = m418c();
        List d = this.f319b.m97d();
        C0106n r = this.f319b.m111r();
        if (d == null && r == null && c == null) {
            return null;
        }
        C0048z c0048z = new C0048z();
        c0048z.f331a = c;
        c0048z.f332b = d;
        c0048z.f333c = r;
        return c0048z;
    }

    protected void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        Parcelable c = this.f319b.m96c();
        if (c != null) {
            bundle.putParcelable("android:support:fragments", c);
        }
        if (this.f328k.m660b() > 0) {
            bundle.putInt("android:support:next_request_index", this.f326i);
            int[] iArr = new int[this.f328k.m660b()];
            String[] strArr = new String[this.f328k.m660b()];
            for (int i = 0; i < this.f328k.m660b(); i++) {
                iArr[i] = this.f328k.m665d(i);
                strArr[i] = (String) this.f328k.m666e(i);
            }
            bundle.putIntArray("android:support:request_indicies", iArr);
            bundle.putStringArray("android:support:request_fragment_who", strArr);
        }
    }

    protected void onStart() {
        super.onStart();
        this.f322e = false;
        this.f323f = false;
        this.f318a.removeMessages(1);
        if (!this.f320c) {
            this.f320c = true;
            this.f319b.m99f();
        }
        this.f319b.m93b();
        this.f319b.m107n();
        this.f319b.m108o();
        this.f319b.m100g();
        this.f319b.m110q();
    }

    public void onStateNotSaved() {
        this.f319b.m93b();
    }

    protected void onStop() {
        super.onStop();
        this.f322e = true;
        this.f318a.sendEmptyMessage(1);
        this.f319b.m103j();
    }

    public void startActivityForResult(Intent intent, int i) {
        if (this.f327j || i == -1 || (-65536 & i) == 0) {
            super.startActivityForResult(intent, i);
            return;
        }
        throw new IllegalArgumentException("Can only use lower 16 bits for requestCode");
    }
}
