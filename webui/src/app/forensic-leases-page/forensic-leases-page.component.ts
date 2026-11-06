import { Component, inject } from '@angular/core'
import { HttpClient, HttpParams } from '@angular/common/http'
import { FormsModule } from '@angular/forms'
import { BreadcrumbsComponent } from '../breadcrumbs/breadcrumbs.component'
import { TableModule } from '@openng/optimus-ui/table'
import { ButtonModule } from '@openng/optimus-ui/button'
import { InputText } from '@openng/optimus-ui/inputtext'
import { MessageService } from '@openng/optimus-ui/api'
import { getErrorMessage } from '../utils'

interface ForensicLog {
    timestamp: string
    address: string
    log: string
    daemonId: number
    daemonLabel: string
}

interface ForensicLogs {
    total: number
    items: ForensicLog[]
}

/**
 * Search Kea legal-log history. The page does not query until a start and end
 * time are set. The server asks the agent to read that range in a read-only
 * transaction.
 */
@Component({
    selector: 'app-forensic-leases-page',
    templateUrl: './forensic-leases-page.component.html',
    styleUrls: ['./forensic-leases-page.component.sass'],
    imports: [BreadcrumbsComponent, FormsModule, TableModule, ButtonModule, InputText],
})
export class ForensicLeasesPageComponent {
    private http = inject(HttpClient)
    private msgSrv = inject(MessageService)

    breadcrumbs = [{ label: 'DHCP' }, { label: 'Forensic Search' }]

    address = ''
    text = ''
    from = ''
    to = ''
    rows: ForensicLog[] = []
    total = 0
    loading = false
    searched = false
    first = 0
    rowsPerPage = 10

    canSearch(): boolean {
        if (!this.from || !this.to) {
            return false
        }
        return new Date(this.from).getTime() <= new Date(this.to).getTime()
    }

    clearResults() {
        this.searched = false
        this.rows = []
        this.total = 0
        this.first = 0
    }

    search() {
        if (!this.canSearch()) {
            this.msgSrv.add({
                severity: 'error',
                summary: 'Choose a time range',
                detail: 'Forensic history is only read when a start and end time are set.',
            })
            return
        }
        this.searched = true
        this.first = 0
        this.load()
    }

    load(event?: { first?: number; rows?: number }) {
        if (!this.searched || !this.canSearch()) {
            return
        }
        if (event) {
            this.first = event.first ?? 0
            this.rowsPerPage = event.rows ?? this.rowsPerPage
        }
        this.loading = true
        this.http
            .get<ForensicLogs>('/api/forensic-leases', { params: this.params(this.first, this.rowsPerPage) })
            .subscribe({
                next: (rsp) => {
                    this.rows = rsp.items ?? []
                    this.total = rsp.total ?? 0
                    this.loading = false
                },
                error: (err) => {
                    this.loading = false
                    this.msgSrv.add({
                        severity: 'error',
                        summary: 'Cannot search forensic history',
                        detail: getErrorMessage(err),
                    })
                },
            })
    }

    download() {
        if (!this.canSearch()) {
            this.msgSrv.add({
                severity: 'error',
                summary: 'Choose a time range',
                detail: 'Download reads only the start and end time you set.',
            })
            return
        }
        this.loading = true
        this.http.get<ForensicLogs>('/api/forensic-leases', { params: this.params(0, 0) }).subscribe({
            next: (rsp) => {
                this.loading = false
                const items = rsp.items ?? []
                const lines = ['timestamp,address,daemon,log']
                for (const row of items) {
                    lines.push(
                        [row.timestamp, row.address, row.daemonLabel, row.log]
                            .map((value) => `"${String(value ?? '').replaceAll('"', '""')}"`)
                            .join(',')
                    )
                }
                const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/csv;charset=utf-8' })
                const url = URL.createObjectURL(blob)
                const link = document.createElement('a')
                link.href = url
                link.download = 'forensic-leases.csv'
                link.click()
                URL.revokeObjectURL(url)
            },
            error: (err) => {
                this.loading = false
                this.msgSrv.add({
                    severity: 'error',
                    summary: 'Cannot download forensic history',
                    detail: getErrorMessage(err),
                })
            },
        })
    }

    private params(start: number, limit: number): HttpParams {
        let params = new HttpParams()
            .set('start', start)
            .set('limit', limit)
            .set('from', new Date(this.from).toISOString())
            .set('to', new Date(this.to).toISOString())
        if (this.address.trim()) {
            params = params.set('address', this.address.trim())
        }
        if (this.text.trim()) {
            params = params.set('text', this.text.trim())
        }
        return params
    }
}
