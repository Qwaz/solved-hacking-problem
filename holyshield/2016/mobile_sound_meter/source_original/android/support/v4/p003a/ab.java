package android.support.v4.p003a;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Parcelable;
import android.support.v4.p012g.C0106n;
import android.util.AttributeSet;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.List;

/* renamed from: android.support.v4.a.ab */
public class ab {
    private final ac f89a;

    private ab(ac acVar) {
        this.f89a = acVar;
    }

    public static final ab m80a(ac acVar) {
        return new ab(acVar);
    }

    public ad m81a() {
        return this.f89a.m129i();
    }

    C0042t m82a(String str) {
        return this.f89a.f93d.m171b(str);
    }

    public View m83a(View view, String str, Context context, AttributeSet attributeSet) {
        return this.f89a.f93d.m151a(view, str, context, attributeSet);
    }

    public void m84a(Configuration configuration) {
        this.f89a.f93d.m156a(configuration);
    }

    public void m85a(Parcelable parcelable, List list) {
        this.f89a.f93d.m158a(parcelable, list);
    }

    public void m86a(C0042t c0042t) {
        this.f89a.f93d.m159a(this.f89a, this.f89a, c0042t);
    }

    public void m87a(C0106n c0106n) {
        this.f89a.m114a(c0106n);
    }

    public void m88a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        this.f89a.m122b(str, fileDescriptor, printWriter, strArr);
    }

    public void m89a(boolean z) {
        this.f89a.m117a(z);
    }

    public boolean m90a(Menu menu) {
        return this.f89a.f93d.m168a(menu);
    }

    public boolean m91a(Menu menu, MenuInflater menuInflater) {
        return this.f89a.f93d.m169a(menu, menuInflater);
    }

    public boolean m92a(MenuItem menuItem) {
        return this.f89a.f93d.m170a(menuItem);
    }

    public void m93b() {
        this.f89a.f93d.m190h();
    }

    public void m94b(Menu menu) {
        this.f89a.f93d.m175b(menu);
    }

    public boolean m95b(MenuItem menuItem) {
        return this.f89a.f93d.m177b(menuItem);
    }

    public Parcelable m96c() {
        return this.f89a.f93d.m189g();
    }

    public List m97d() {
        return this.f89a.f93d.m188f();
    }

    public void m98e() {
        this.f89a.f93d.m191i();
    }

    public void m99f() {
        this.f89a.f93d.m192j();
    }

    public void m100g() {
        this.f89a.f93d.m193k();
    }

    public void m101h() {
        this.f89a.f93d.m194l();
    }

    public void m102i() {
        this.f89a.f93d.m195m();
    }

    public void m103j() {
        this.f89a.f93d.m196n();
    }

    public void m104k() {
        this.f89a.f93d.m197o();
    }

    public void m105l() {
        this.f89a.f93d.m199q();
    }

    public void m106m() {
        this.f89a.f93d.m200r();
    }

    public boolean m107n() {
        return this.f89a.f93d.m183d();
    }

    public void m108o() {
        this.f89a.m131k();
    }

    public void m109p() {
        this.f89a.m132l();
    }

    public void m110q() {
        this.f89a.m133m();
    }

    public C0106n m111r() {
        return this.f89a.m134n();
    }
}
