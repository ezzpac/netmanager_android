$(document).ready(function () {

    let table;

    // Initialize DataTables
    if ($('#devicesTable').length) {
        table = $('#devicesTable').DataTable({
            language: {
                url: '//cdn.datatables.net/plug-ins/1.13.4/i18n/pt-BR.json'
            },
            responsive: true,
            order: [[0, "asc"]],
            dom: 'lrtip', // Restore length menu (l)
            initComplete: function () {
                // Move length menu to custom container and clean up labels
                var lengthMenu = $('.dataTables_length');
                var lengthLabel = lengthMenu.find('label').addClass('d-flex align-items-center gap-2 m-0');

                // Remove the text "Show" and "entries" to keep it compact
                lengthLabel.contents().filter(function () {
                    return this.nodeType === 3;
                }).remove();

                // Add an icon and style the select
                lengthLabel.prepend('<i class="fas fa-list-numeric text-muted me-1" title="Registros por página"></i>');
                lengthLabel.find('select').addClass('form-select form-select-sm w-auto').css('padding', '0.25rem 2rem 0.25rem 0.5rem');

                $('#lengthContainer').empty().append(lengthMenu);

                // Create custom search input
                var searchHtml = $('<div class="input-group ms-auto" style="max-width: 300px;">' +
                    '<span class="input-group-text bg-white border-end-0">' +
                    '<i class="fas fa-search text-muted"></i>' +
                    '</span>' +
                    '<input type="text" class="form-control border-start-0 ps-0" placeholder="Pesquisar...">' +
                    '</div>');

                var searchInput = searchHtml.find('input');
                $('#searchContainer').empty().append(searchHtml);

                // Bind search event
                searchInput.on('keyup', function () {
                    table.search(this.value).draw();
                });
            }
        });
    }

    // Filtro por Grupo (coluna 4)
    $('#filterGroup').on('change', function () {
        table.column(4).search(this.value).draw();
    });

    // Filtro por Tipo (coluna 5) - Removido em favor do filtro server-side
    // $('#filterType').on('change', function () {
    //     table.column(5).search(this.value).draw();
    // });

    // Confirmation for delete
    $('.btn-delete').on('click', function (e) {
        if (!confirm('Tem certeza que deseja excluir este dispositivo?')) {
            e.preventDefault();
        }
    });

    // Auto-dismiss alerts
    setTimeout(function () {
        $('.alert').fadeOut('slow');
    }, 5000);

    // Theme Toggle Logic
    const themeToggle = $('#themeToggle');
    const themeIcon = themeToggle.find('i');

    function updateThemeIcon(theme) {
        if (theme === 'dark') {
            themeIcon.removeClass('fa-moon').addClass('fa-sun');
        } else {
            themeIcon.removeClass('fa-sun').addClass('fa-moon');
        }
    }

    // Initialize icon
    updateThemeIcon(document.documentElement.getAttribute('data-bs-theme'));

    themeToggle.on('click', function () {
        let currentTheme = document.documentElement.getAttribute('data-bs-theme');
        let newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });
});
