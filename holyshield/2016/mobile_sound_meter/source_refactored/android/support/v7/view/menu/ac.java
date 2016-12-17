package android.support.v7.view.menu;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.support.v4.p008d.p009a.C0089a;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SubMenu;

class ac extends C0263e implements Menu {
    ac(Context context, C0089a c0089a) {
        super(context, c0089a);
    }

    public MenuItem add(int i) {
        return m2087a(((C0089a) this.b).add(i));
    }

    public MenuItem add(int i, int i2, int i3, int i4) {
        return m2087a(((C0089a) this.b).add(i, i2, i3, i4));
    }

    public MenuItem add(int i, int i2, int i3, CharSequence charSequence) {
        return m2087a(((C0089a) this.b).add(i, i2, i3, charSequence));
    }

    public MenuItem add(CharSequence charSequence) {
        return m2087a(((C0089a) this.b).add(charSequence));
    }

    public int addIntentOptions(int i, int i2, int i3, ComponentName componentName, Intent[] intentArr, Intent intent, int i4, MenuItem[] menuItemArr) {
        MenuItem[] menuItemArr2 = null;
        if (menuItemArr != null) {
            menuItemArr2 = new MenuItem[menuItemArr.length];
        }
        int addIntentOptions = ((C0089a) this.b).addIntentOptions(i, i2, i3, componentName, intentArr, intent, i4, menuItemArr2);
        if (menuItemArr2 != null) {
            int length = menuItemArr2.length;
            for (int i5 = 0; i5 < length; i5++) {
                menuItemArr[i5] = m2087a(menuItemArr2[i5]);
            }
        }
        return addIntentOptions;
    }

    public SubMenu addSubMenu(int i) {
        return m2088a(((C0089a) this.b).addSubMenu(i));
    }

    public SubMenu addSubMenu(int i, int i2, int i3, int i4) {
        return m2088a(((C0089a) this.b).addSubMenu(i, i2, i3, i4));
    }

    public SubMenu addSubMenu(int i, int i2, int i3, CharSequence charSequence) {
        return m2088a(((C0089a) this.b).addSubMenu(i, i2, i3, charSequence));
    }

    public SubMenu addSubMenu(CharSequence charSequence) {
        return m2088a(((C0089a) this.b).addSubMenu(charSequence));
    }

    public void clear() {
        m2089a();
        ((C0089a) this.b).clear();
    }

    public void close() {
        ((C0089a) this.b).close();
    }

    public MenuItem findItem(int i) {
        return m2087a(((C0089a) this.b).findItem(i));
    }

    public MenuItem getItem(int i) {
        return m2087a(((C0089a) this.b).getItem(i));
    }

    public boolean hasVisibleItems() {
        return ((C0089a) this.b).hasVisibleItems();
    }

    public boolean isShortcutKey(int i, KeyEvent keyEvent) {
        return ((C0089a) this.b).isShortcutKey(i, keyEvent);
    }

    public boolean performIdentifierAction(int i, int i2) {
        return ((C0089a) this.b).performIdentifierAction(i, i2);
    }

    public boolean performShortcut(int i, KeyEvent keyEvent, int i2) {
        return ((C0089a) this.b).performShortcut(i, keyEvent, i2);
    }

    public void removeGroup(int i) {
        m2090a(i);
        ((C0089a) this.b).removeGroup(i);
    }

    public void removeItem(int i) {
        m2091b(i);
        ((C0089a) this.b).removeItem(i);
    }

    public void setGroupCheckable(int i, boolean z, boolean z2) {
        ((C0089a) this.b).setGroupCheckable(i, z, z2);
    }

    public void setGroupEnabled(int i, boolean z) {
        ((C0089a) this.b).setGroupEnabled(i, z);
    }

    public void setGroupVisible(int i, boolean z) {
        ((C0089a) this.b).setGroupVisible(i, z);
    }

    public void setQwertyMode(boolean z) {
        ((C0089a) this.b).setQwertyMode(z);
    }

    public int size() {
        return ((C0089a) this.b).size();
    }
}
