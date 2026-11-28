#include <gtk/gtk.h>

static GtkWindow *window;
static GtkWidget *entry, *label;
static const char *record_path;
static gboolean pressed;

static void record(void) {
    gchar *line = g_strdup_printf("%d\t%d\t%s\n", gtk_window_is_active(window),
                                  pressed, gtk_editable_get_text(GTK_EDITABLE(entry)));
    if (!g_file_set_contents(record_path, line, -1, NULL))
        g_error("could not record GTK fixture state");
    g_free(line);
}

static void changed(GtkEditable *widget, gpointer data) {
    (void)widget;
    (void)data;
    record();
}

static void active_changed(GObject *widget, GParamSpec *property, gpointer data) {
    (void)widget;
    (void)property;
    (void)data;
    record();
}

static void apply(GtkButton *button, gpointer data) {
    (void)button;
    (void)data;
    pressed = TRUE;
    gtk_label_set_text(GTK_LABEL(label), "Ready");
    record();
}

int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    g_set_prgname(argv[1]);
    g_set_application_name(argv[1]);
    record_path = argv[2];
    gtk_init();
    window = GTK_WINDOW(gtk_window_new());
    gtk_window_set_title(window, argv[1]);
    gtk_window_set_default_size(window, 380, 150);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_window_set_child(window, box);
    entry = gtk_entry_new();
    gtk_accessible_update_property(GTK_ACCESSIBLE(entry), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   "Fixture Message", -1);
    gtk_box_append(GTK_BOX(box), entry);
    GtkWidget *secret = gtk_password_entry_new();
    gtk_accessible_update_property(GTK_ACCESSIBLE(secret), GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   "Fixture Password", -1);
    gtk_box_append(GTK_BOX(box), secret);
    GtkWidget *button = gtk_button_new_with_label("Fixture Apply");
    gtk_box_append(GTK_BOX(box), button);
    label = gtk_label_new("Awaiting");
    gtk_box_append(GTK_BOX(box), label);
    g_signal_connect(entry, "changed", G_CALLBACK(changed), NULL);
    g_signal_connect(window, "notify::is-active", G_CALLBACK(active_changed), NULL);
    g_signal_connect(button, "clicked", G_CALLBACK(apply), NULL);
    gtk_window_set_focus(window, entry);
    gtk_window_present(window);
    record();
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);
    return 0;
}
